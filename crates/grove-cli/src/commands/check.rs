use crate::client::DaemonClient;
use crate::commands::CommandError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConflictRow {
    score: String,
    other_workspace: String,
    summary: String,
    overlaps: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckEvaluation {
    workspace_name: String,
    conflicts: Vec<ConflictRow>,
}

/// Execute the `check` command — report conflicts for the current worktree.
///
/// Silent (exit 0) when clean. Prints terse one-liners and exits non-zero when
/// the current worktree has non-Green conflicts with other worktrees.
pub async fn execute(client: &DaemonClient, json: bool) -> Result<(), CommandError> {
    let cwd = std::env::current_dir()
        .map_err(|e| CommandError::DaemonError(format!("failed to get current directory: {e}")))?;
    let cwd = canonicalize_or_identity(&cwd);

    // Fetch workspaces and analyses in parallel-ish (sequential for now, both fast).
    let ws_resp = client.list_workspaces().await?;
    if !ws_resp.ok {
        return Err(CommandError::DaemonError(
            ws_resp.error.unwrap_or_else(|| "unknown error".to_string()),
        ));
    }
    let workspaces = ws_resp
        .data
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    // Fetch analyses.
    let analyses_resp = client.get_all_analyses().await?;
    let analyses = analyses_resp
        .data
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    let evaluation = evaluate_check_payload(&cwd, &workspaces, &analyses)?;

    if json {
        println!("{}", render_json_output(&evaluation));
    } else if !evaluation.conflicts.is_empty() {
        for conflict in &evaluation.conflicts {
            let label = match conflict.score.as_str() {
                "Yellow" => "minor",
                "Red" => "conflict",
                "Black" => "breaking",
                other => other,
            };
            eprintln!(
                "[{label}] {}: {}",
                conflict.other_workspace, conflict.summary
            );
        }
        eprintln!("\nRun `grove conflicts <this-branch> <other-branch>` for full details.");
    }

    if evaluation.conflicts.is_empty() {
        Ok(())
    } else {
        // Exit directly — the one-liners on stderr are the output.
        // Returning an error would add a redundant "error: ..." wrapper.
        std::process::exit(1)
    }
}

fn canonicalize_or_identity(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn find_current_workspace<'a>(
    workspaces: &'a [serde_json::Value],
    cwd: &Path,
) -> Option<&'a serde_json::Value> {
    workspaces.iter().find(|ws| {
        let Some(ws_path) = ws.get("path").and_then(|v| v.as_str()) else {
            return false;
        };
        let ws_canonical = canonicalize_or_identity(Path::new(ws_path));
        cwd.starts_with(&ws_canonical)
    })
}

fn build_id_to_name(workspaces: &[serde_json::Value]) -> HashMap<&str, &str> {
    workspaces
        .iter()
        .filter_map(|ws| {
            let id = ws.get("id")?.as_str()?;
            let name = ws.get("name")?.as_str()?;
            Some((id, name))
        })
        .collect()
}

fn evaluate_check_payload(
    cwd: &Path,
    workspaces: &[serde_json::Value],
    analyses: &[serde_json::Value],
) -> Result<CheckEvaluation, CommandError> {
    let current_ws = find_current_workspace(workspaces, cwd).ok_or_else(|| {
        CommandError::DaemonError(
            "current directory does not match any tracked worktree".to_string(),
        )
    })?;

    let current_id = current_ws.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let current_name = current_ws
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string();
    let id_to_name = build_id_to_name(workspaces);

    let conflicts = analyses
        .iter()
        .filter_map(|analysis| {
            let ws_a = analysis
                .get("workspace_a")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ws_b = analysis
                .get("workspace_b")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let score = analysis
                .get("score")
                .and_then(|v| v.as_str())
                .unwrap_or("Green");
            if score == "Green" || (ws_a != current_id && ws_b != current_id) {
                return None;
            }

            let other_id = if ws_a == current_id { ws_b } else { ws_a };
            let other_name = id_to_name
                .get(other_id)
                .copied()
                .unwrap_or(other_id)
                .to_string();
            let overlaps_array = analysis
                .get("overlaps")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            Some(ConflictRow {
                score: score.to_string(),
                other_workspace: other_name,
                summary: summarize_overlaps(&overlaps_array),
                overlaps: analysis.get("overlaps").cloned(),
            })
        })
        .collect();

    Ok(CheckEvaluation {
        workspace_name: current_name,
        conflicts,
    })
}

fn render_json_output(evaluation: &CheckEvaluation) -> String {
    let conflicts: Vec<serde_json::Value> = evaluation
        .conflicts
        .iter()
        .map(|conflict| {
            serde_json::json!({
                "score": conflict.score,
                "other_workspace": conflict.other_workspace,
                "summary": conflict.summary,
                "overlaps": conflict.overlaps,
            })
        })
        .collect();
    let output = serde_json::json!({
        "workspace": evaluation.workspace_name,
        "clean": conflicts.is_empty(),
        "conflicts": conflicts,
    });
    serde_json::to_string_pretty(&output).unwrap_or_default()
}

/// Produce a short one-line summary of the overlaps for a pair.
fn summarize_overlaps(overlaps: &[serde_json::Value]) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Count overlap types.
    let dep_count = overlaps
        .iter()
        .filter(|o| o.get("Dependency").is_some())
        .count();
    let symbol_count = overlaps
        .iter()
        .filter(|o| o.get("Symbol").is_some())
        .count();
    let hunk_count = overlaps.iter().filter(|o| o.get("Hunk").is_some()).count();
    let file_count = overlaps.iter().filter(|o| o.get("File").is_some()).count();
    let schema_count = overlaps
        .iter()
        .filter(|o| o.get("Schema").is_some())
        .count();

    // Prioritize the most severe overlap types.
    if dep_count > 0 {
        // Show first dependency path.
        if let Some(dep) = overlaps.iter().find_map(|o| o.get("Dependency")) {
            let changed = dep
                .get("changed_file")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let affected = dep
                .get("affected_file")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let mut s = format!("export change in {changed} breaks import in {affected}");
            if dep_count > 1 {
                s.push_str(&format!(" (+{} more)", dep_count - 1));
            }
            parts.push(s);
        }
    }
    if symbol_count > 0
        && let Some(sym) = overlaps.iter().find_map(|o| o.get("Symbol"))
    {
        let name = sym
            .get("symbol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let path = sym.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let mut s = format!("both branches modify {name}() in {path}");
        if symbol_count > 1 {
            s.push_str(&format!(" (+{} more)", symbol_count - 1));
        }
        parts.push(s);
    }
    if hunk_count > 0
        && let Some(hunk) = overlaps.iter().find_map(|o| o.get("Hunk"))
    {
        let path = hunk.get("path").and_then(|v| v.as_str()).unwrap_or("?");
        let mut s = format!("overlapping line changes in {path}");
        if hunk_count > 1 {
            s.push_str(&format!(" (+{} more)", hunk_count - 1));
        }
        parts.push(s);
    }
    if file_count > 0 && parts.is_empty() {
        // Only show file overlaps if nothing more specific was found.
        parts.push(format!("{file_count} file(s) modified by both branches"));
    }
    if schema_count > 0 {
        parts.push(format!("{schema_count} schema conflict(s)"));
    }

    if parts.is_empty() {
        "conflict detected".to_string()
    } else {
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ws(id: &str, name: &str, path: &Path) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "path": path.to_string_lossy()
        })
    }

    fn hunk_overlap(path: &str) -> serde_json::Value {
        serde_json::json!({
            "Hunk": {
                "path": path,
                "a_range": {"start": 10, "end": 20},
                "b_range": {"start": 15, "end": 25},
                "distance": 0
            }
        })
    }

    fn symbol_overlap(path: &str, symbol: &str) -> serde_json::Value {
        serde_json::json!({
            "Symbol": {
                "path": path,
                "symbol_name": symbol
            }
        })
    }

    #[test]
    fn summarize_empty_overlaps() {
        assert_eq!(summarize_overlaps(&[]), "conflict detected");
    }

    #[test]
    fn summarize_dependency_overlap() {
        let overlaps = vec![serde_json::json!({
            "Dependency": {
                "changed_file": "src/shared.ts",
                "affected_file": "src/api.ts",
            }
        })];
        let summary = summarize_overlaps(&overlaps);
        assert_eq!(
            summary,
            "export change in src/shared.ts breaks import in src/api.ts"
        );
    }

    #[test]
    fn summarize_multiple_dependencies() {
        let overlaps = vec![
            serde_json::json!({
                "Dependency": {
                    "changed_file": "src/shared.ts",
                    "affected_file": "src/api.ts",
                }
            }),
            serde_json::json!({
                "Dependency": {
                    "changed_file": "src/utils.ts",
                    "affected_file": "src/main.ts",
                }
            }),
        ];
        let summary = summarize_overlaps(&overlaps);
        assert!(summary.contains("export change in src/shared.ts breaks import in src/api.ts"));
        assert!(summary.contains("+1 more"));
    }

    #[test]
    fn summarize_symbol_overlap() {
        let overlaps = vec![serde_json::json!({
            "Symbol": {
                "path": "src/auth.ts",
                "symbol_name": "authenticate",
            }
        })];
        let summary = summarize_overlaps(&overlaps);
        assert_eq!(
            summary,
            "both branches modify authenticate() in src/auth.ts"
        );
    }

    #[test]
    fn summarize_hunk_overlap() {
        let overlaps = vec![serde_json::json!({
            "Hunk": {
                "path": "src/main.ts",
                "a_range": {"start": 10, "end": 20},
                "b_range": {"start": 12, "end": 18},
            }
        })];
        let summary = summarize_overlaps(&overlaps);
        assert_eq!(summary, "overlapping line changes in src/main.ts");
    }

    #[test]
    fn summarize_file_only_overlap() {
        let overlaps = vec![
            serde_json::json!({"File": {"path": "src/a.ts"}}),
            serde_json::json!({"File": {"path": "src/b.ts"}}),
        ];
        let summary = summarize_overlaps(&overlaps);
        assert_eq!(summary, "2 file(s) modified by both branches");
    }

    #[test]
    fn summarize_mixed_overlaps_prioritizes_severity() {
        let overlaps = vec![
            serde_json::json!({"File": {"path": "src/a.ts"}}),
            serde_json::json!({
                "Dependency": {
                    "changed_file": "src/shared.ts",
                    "affected_file": "src/api.ts",
                }
            }),
            serde_json::json!({
                "Symbol": {
                    "path": "src/auth.ts",
                    "symbol_name": "login",
                }
            }),
        ];
        let summary = summarize_overlaps(&overlaps);
        // Dependency and symbol shown, file-only suppressed.
        assert!(summary.contains("export change in src/shared.ts breaks import in src/api.ts"));
        assert!(summary.contains("both branches modify login() in src/auth.ts"));
        assert!(!summary.contains("file(s) modified"));
    }

    #[test]
    fn find_current_workspace_matches_nested_path_using_canonical_paths() {
        let temp = tempfile::tempdir().unwrap();
        let ws_root = temp.path().join("worktree-a");
        let nested = ws_root.join("src").join("module");
        std::fs::create_dir_all(&nested).unwrap();
        let nested = std::fs::canonicalize(&nested).unwrap();

        let workspaces = vec![ws("a", "alpha", &ws_root)];
        let found = find_current_workspace(&workspaces, &nested).unwrap();
        assert_eq!(found.get("name").and_then(|v| v.as_str()), Some("alpha"));
    }

    #[test]
    fn evaluate_check_payload_returns_error_for_untracked_cwd() {
        let temp = tempfile::tempdir().unwrap();
        let other = temp.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        let workspaces = vec![ws("a", "alpha", &temp.path().join("tracked"))];
        let err = evaluate_check_payload(&other, &workspaces, &[]).unwrap_err();
        assert!(
            err.to_string()
                .contains("current directory does not match any tracked worktree")
        );
    }

    #[test]
    fn evaluate_check_payload_filters_green_and_unrelated_pairs() {
        let temp = tempfile::tempdir().unwrap();
        let ws_a = temp.path().join("a");
        let ws_b = temp.path().join("b");
        let ws_c = temp.path().join("c");
        std::fs::create_dir_all(&ws_a).unwrap();
        std::fs::create_dir_all(&ws_b).unwrap();
        std::fs::create_dir_all(&ws_c).unwrap();

        let workspaces = vec![
            ws("a", "alpha", &ws_a),
            ws("b", "beta", &ws_b),
            ws("c", "gamma", &ws_c),
        ];
        let analyses = vec![
            serde_json::json!({
                "workspace_a": "a",
                "workspace_b": "b",
                "score": "Red",
                "overlaps": [symbol_overlap("src/auth.ts", "login")]
            }),
            serde_json::json!({
                "workspace_a": "a",
                "workspace_b": "c",
                "score": "Green",
                "overlaps": []
            }),
            serde_json::json!({
                "workspace_a": "x",
                "workspace_b": "y",
                "score": "Black",
                "overlaps": [hunk_overlap("src/main.ts")]
            }),
        ];

        let cwd = std::fs::canonicalize(&ws_a).unwrap();
        let eval = evaluate_check_payload(&cwd, &workspaces, &analyses).unwrap();
        assert_eq!(eval.workspace_name, "alpha");
        assert_eq!(eval.conflicts.len(), 1);
        assert_eq!(eval.conflicts[0].other_workspace, "beta");
        assert_eq!(eval.conflicts[0].score, "Red");
        assert!(eval.conflicts[0].summary.contains("login"));
    }

    #[test]
    fn render_json_output_has_expected_shape() {
        let evaluation = CheckEvaluation {
            workspace_name: "alpha".to_string(),
            conflicts: vec![ConflictRow {
                score: "Yellow".to_string(),
                other_workspace: "beta".to_string(),
                summary: "overlapping line changes in src/main.ts".to_string(),
                overlaps: Some(serde_json::json!([hunk_overlap("src/main.ts")])),
            }],
        };

        let rendered = render_json_output(&evaluation);
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["workspace"], "alpha");
        assert_eq!(value["clean"], false);
        assert_eq!(value["conflicts"][0]["score"], "Yellow");
        assert_eq!(value["conflicts"][0]["other_workspace"], "beta");
    }

    #[test]
    fn canonicalize_or_identity_keeps_path_when_missing() {
        let missing = PathBuf::from("/definitely/nonexistent/path/for/grove");
        let value = canonicalize_or_identity(&missing);
        assert_eq!(value, missing);
    }
}
