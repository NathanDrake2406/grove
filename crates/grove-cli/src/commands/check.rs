use crate::client::DaemonClient;
use crate::commands::CommandError;
use std::collections::HashMap;
use std::path::Path;

/// Execute the `check` command — report conflicts for the current worktree.
///
/// Silent (exit 0) when clean. Prints terse one-liners and exits non-zero when
/// the current worktree has non-Green conflicts with other worktrees.
pub async fn execute(client: &DaemonClient, json: bool) -> Result<(), CommandError> {
    let cwd = std::env::current_dir().map_err(|e| {
        CommandError::DaemonError(format!("failed to get current directory: {e}"))
    })?;
    let cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);

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

    // Find which workspace matches the current directory.
    let current_ws = workspaces.iter().find(|ws| {
        let Some(ws_path) = ws.get("path").and_then(|v| v.as_str()) else {
            return false;
        };
        let ws_path = Path::new(ws_path);
        let ws_canonical =
            std::fs::canonicalize(ws_path).unwrap_or_else(|_| ws_path.to_path_buf());
        cwd.starts_with(&ws_canonical)
    });

    let Some(current_ws) = current_ws else {
        return Err(CommandError::DaemonError(
            "current directory does not match any tracked worktree".to_string(),
        ));
    };

    let current_id = current_ws
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let current_name = current_ws
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("?");

    // Build ID → name lookup.
    let id_to_name: HashMap<&str, &str> = workspaces
        .iter()
        .filter_map(|ws| {
            let id = ws.get("id")?.as_str()?;
            let name = ws.get("name")?.as_str()?;
            Some((id, name))
        })
        .collect();

    // Fetch analyses.
    let analyses_resp = client.get_all_analyses().await?;
    let analyses = analyses_resp
        .data
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    // Filter: involves this workspace + non-Green score.
    let conflicts: Vec<_> = analyses
        .iter()
        .filter(|a| {
            let ws_a = a.get("workspace_a").and_then(|v| v.as_str()).unwrap_or("");
            let ws_b = a.get("workspace_b").and_then(|v| v.as_str()).unwrap_or("");
            let score = a.get("score").and_then(|v| v.as_str()).unwrap_or("Green");
            (ws_a == current_id || ws_b == current_id) && score != "Green"
        })
        .collect();

    let json_conflicts: Vec<serde_json::Value> = conflicts
        .iter()
        .map(|a| {
            let ws_a = a.get("workspace_a").and_then(|v| v.as_str()).unwrap_or("");
            let ws_b = a.get("workspace_b").and_then(|v| v.as_str()).unwrap_or("");
            let other_id = if ws_a == current_id { ws_b } else { ws_a };
            let other_name = id_to_name.get(other_id).copied().unwrap_or(other_id);
            let overlaps = a.get("overlaps").and_then(|v| v.as_array());
            let summary = summarize_overlaps(overlaps.map(Vec::as_slice).unwrap_or(&[]));
            serde_json::json!({
                "score": a.get("score"),
                "other_workspace": other_name,
                "summary": summary,
                "overlaps": a.get("overlaps"),
            })
        })
        .collect();

    if json {
        let output = serde_json::json!({
            "workspace": current_name,
            "clean": conflicts.is_empty(),
            "conflicts": json_conflicts,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    } else if !conflicts.is_empty() {
        for c in &json_conflicts {
            let score = c.get("score").and_then(|v| v.as_str()).unwrap_or("?");
            let other = c
                .get("other_workspace")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let summary = c.get("summary").and_then(|v| v.as_str()).unwrap_or("");
            eprintln!("[{score}] {other}: {summary}");
        }
    }

    if conflicts.is_empty() {
        Ok(())
    } else {
        // Exit directly — the one-liners on stderr are the output.
        // Returning an error would add a redundant "error: ..." wrapper.
        std::process::exit(1)
    }
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
    let hunk_count = overlaps
        .iter()
        .filter(|o| o.get("Hunk").is_some())
        .count();
    let file_count = overlaps
        .iter()
        .filter(|o| o.get("File").is_some())
        .count();
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
            let mut s = format!("{changed} -> {affected}");
            if dep_count > 1 {
                s.push_str(&format!(" (+{} more)", dep_count - 1));
            }
            parts.push(s);
        }
    }
    if symbol_count > 0 {
        if let Some(sym) = overlaps.iter().find_map(|o| o.get("Symbol")) {
            let name = sym
                .get("symbol_name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let path = sym.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let mut s = format!("{name}() in {path}");
            if symbol_count > 1 {
                s.push_str(&format!(" (+{} more)", symbol_count - 1));
            }
            parts.push(s);
        }
    }
    if hunk_count > 0 {
        if let Some(hunk) = overlaps.iter().find_map(|o| o.get("Hunk")) {
            let path = hunk.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let mut s = format!("overlapping lines in {path}");
            if hunk_count > 1 {
                s.push_str(&format!(" (+{} more)", hunk_count - 1));
            }
            parts.push(s);
        }
    }
    if file_count > 0 && parts.is_empty() {
        // Only show file overlaps if nothing more specific was found.
        parts.push(format!("{file_count} shared file(s)"));
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
        assert_eq!(summary, "src/shared.ts -> src/api.ts");
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
        assert!(summary.contains("src/shared.ts -> src/api.ts"));
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
        assert_eq!(summary, "authenticate() in src/auth.ts");
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
        assert_eq!(summary, "overlapping lines in src/main.ts");
    }

    #[test]
    fn summarize_file_only_overlap() {
        let overlaps = vec![
            serde_json::json!({"File": {"path": "src/a.ts"}}),
            serde_json::json!({"File": {"path": "src/b.ts"}}),
        ];
        let summary = summarize_overlaps(&overlaps);
        assert_eq!(summary, "2 shared file(s)");
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
        assert!(summary.contains("src/shared.ts -> src/api.ts"));
        assert!(summary.contains("login() in src/auth.ts"));
        assert!(!summary.contains("shared file"));
    }
}
