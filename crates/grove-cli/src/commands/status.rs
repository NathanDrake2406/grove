use crate::client::DaemonClient;
use crate::commands::CommandError;
use std::collections::HashMap;
use std::fmt::Write as _;

/// Execute the `status` command, showing a workspace overview with conflicts.
pub async fn execute(client: &DaemonClient, json: bool) -> Result<(), CommandError> {
    let status_resp = client.status().await?;
    if !status_resp.ok {
        let message = status_resp
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(CommandError::DaemonError(message));
    }
    let status_data = status_resp.data.unwrap_or_default();

    // Fetch workspaces and analyses for both JSON and plain-text output.
    let ws_resp = client.list_workspaces().await?;
    let workspaces = ws_resp
        .data
        .and_then(|v| if v.is_array() { Some(v) } else { None })
        .unwrap_or_else(|| serde_json::json!([]));

    let analyses_resp = client.get_all_analyses().await?;
    let analyses = analyses_resp
        .data
        .and_then(|v| if v.is_array() { Some(v) } else { None })
        .unwrap_or_else(|| serde_json::json!([]));

    if json {
        let merged = build_status_json(&status_data, &workspaces, &analyses);
        println!(
            "{}",
            serde_json::to_string_pretty(&merged).unwrap_or_default()
        );
        return Ok(());
    }

    println!(
        "{}",
        format_smart_status(&status_data, &workspaces, &analyses)
    );
    Ok(())
}

fn build_status_json(
    status_data: &serde_json::Value,
    workspaces: &serde_json::Value,
    analyses: &serde_json::Value,
) -> serde_json::Value {
    let workspace_count = status_data
        .get("workspace_count")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| workspaces.as_array().map_or(0, |items| items.len() as u64));
    let analysis_count = status_data
        .get("analysis_count")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| analyses.as_array().map_or(0, |items| items.len() as u64));
    let base_commit = status_data
        .get("base_commit")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    serde_json::json!({
        "workspace_count": workspace_count,
        "analysis_count": analysis_count,
        "base_commit": base_commit,
        "workspaces": workspaces,
        "analyses": analyses,
    })
}

/// Format a status data value for plain-text rendering (extracted for testing).
pub fn format_status_output(data: &serde_json::Value) -> String {
    let workspace_count = data
        .get("workspace_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let analysis_count = data
        .get("analysis_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let base_commit = data
        .get("base_commit")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");

    let mut out = String::new();
    out.push_str("Grove Status\n");
    out.push_str(&"─".repeat(40));
    out.push('\n');
    let _ = writeln!(out, "  Workspaces:  {workspace_count}");
    let _ = writeln!(out, "  Analyses:    {analysis_count}");
    let _ = writeln!(out, "  Base commit: {}", format_commit(base_commit));
    out
}

/// Format a smart status view combining workspace list, conflicts, and merge guidance.
pub fn format_smart_status(
    data: &serde_json::Value,
    workspaces: &serde_json::Value,
    analyses: &serde_json::Value,
) -> String {
    let workspace_count = data
        .get("workspace_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let base_commit = data
        .get("base_commit")
        .and_then(|v| v.as_str())
        .unwrap_or("(none)");

    // Build UUID → name lookup.
    let id_to_name = build_id_name_map(workspaces);

    let mut out = String::new();
    out.push_str("Grove Status\n");
    out.push_str(&"\u{2500}".repeat(50));
    out.push('\n');
    let _ = writeln!(
        out,
        "  {} worktrees  |  base: {}",
        workspace_count,
        format_commit(base_commit)
    );
    out.push('\n');

    // List worktrees.
    if let Some(ws_array) = workspaces.as_array() {
        for ws in ws_array {
            let name = ws.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let branch = ws
                .get("branch")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .strip_prefix("refs/heads/")
                .unwrap_or("");
            if branch == name || branch.is_empty() {
                let _ = writeln!(out, "  {name}");
            } else {
                let _ = writeln!(out, "  {name}  ({branch})");
            }
        }
        out.push('\n');
    }

    // Separate conflicts from clean pairs.
    let analyses = analyses.as_array().map(Vec::as_slice).unwrap_or(&[]);
    let conflict_count = analyses
        .iter()
        .filter(|analysis| {
            let score = analysis
                .get("score")
                .and_then(|value| value.as_str())
                .unwrap_or("Green");
            score != "Green"
        })
        .count();

    if conflict_count == 0 {
        out.push_str("  All worktrees clean \u{2014} no conflicts detected.\n");
        return out;
    }

    let _ = writeln!(out, "  {} conflict(s):", conflict_count);
    out.push('\n');

    for analysis in analyses.iter().filter(|analysis| {
        let score = analysis
            .get("score")
            .and_then(|value| value.as_str())
            .unwrap_or("Green");
        score != "Green"
    }) {
        let score = analysis
            .get("score")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let ws_a_id = analysis
            .get("workspace_a")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let ws_b_id = analysis
            .get("workspace_b")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let name_a = id_to_name.get(ws_a_id).copied().unwrap_or(ws_a_id);
        let name_b = id_to_name.get(ws_b_id).copied().unwrap_or(ws_b_id);
        let overlaps = analysis
            .get("overlaps")
            .and_then(|v| v.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[]);

        let _ = writeln!(out, "  [{score}] {name_a} <-> {name_b}");
        out.push('\n');
        out.push_str(&format_overlaps_grouped(overlaps));
        out.push('\n');
    }

    out
}

/// Build a map from workspace ID to workspace name.
fn build_id_name_map<'a>(workspaces: &'a serde_json::Value) -> HashMap<&'a str, &'a str> {
    let mut map = HashMap::new();
    if let Some(arr) = workspaces.as_array() {
        for ws in arr {
            if let (Some(id), Some(name)) = (
                ws.get("id").and_then(|v| v.as_str()),
                ws.get("name").and_then(|v| v.as_str()),
            ) {
                map.insert(id, name);
            }
        }
    }
    map
}

/// Group overlaps by type and format with section headers.
fn format_overlaps_grouped(overlaps: &[serde_json::Value]) -> String {
    let mut out = String::new();

    if overlaps.iter().any(|overlap| overlap.get("File").is_some()) {
        out.push_str("    Both branches edit the same files:\n");
        for overlap in overlaps {
            if let Some(data) = overlap.get("File") {
                let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                let _ = writeln!(out, "      {path}");
            }
        }
    }

    if overlaps.iter().any(|overlap| overlap.get("Hunk").is_some()) {
        out.push_str("    Both branches change the same lines:\n");
        for overlap in overlaps {
            if let Some(data) = overlap.get("Hunk") {
                let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                let a_start = data
                    .get("a_range")
                    .and_then(|v| v.get("start"))
                    .and_then(|v| v.as_u64());
                let a_end = data
                    .get("a_range")
                    .and_then(|v| v.get("end"))
                    .and_then(|v| v.as_u64());
                match (a_start, a_end) {
                    (Some(start), Some(end)) => {
                        let _ = writeln!(out, "      {path}:{start}-{end}");
                    }
                    _ => {
                        let _ = writeln!(out, "      {path}");
                    }
                }
            }
        }
    }

    if overlaps
        .iter()
        .any(|overlap| overlap.get("Symbol").is_some())
    {
        out.push_str("    Both branches modify the same functions:\n");
        for overlap in overlaps {
            if let Some(data) = overlap.get("Symbol") {
                let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
                let name = data
                    .get("symbol_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let _ = writeln!(out, "      {name}() in {path}");
            }
        }
    }

    if overlaps
        .iter()
        .any(|overlap| overlap.get("Dependency").is_some())
    {
        out.push_str("    One branch's changes affect the other's imports:\n");
        for overlap in overlaps {
            if let Some(data) = overlap.get("Dependency") {
                let changed = data
                    .get("changed_file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let affected = data
                    .get("affected_file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let _ = writeln!(out, "      {changed} \u{2192} {affected}");
            }
        }
    }

    if overlaps
        .iter()
        .any(|overlap| overlap.get("Schema").is_some())
    {
        out.push_str("    Both branches touch shared config/schemas:\n");
        for overlap in overlaps {
            if let Some(data) = overlap.get("Schema") {
                let category = data.get("category").and_then(|v| v.as_str()).unwrap_or("?");
                let a_file = data.get("a_file").and_then(|v| v.as_str()).unwrap_or("?");
                let b_file = data.get("b_file").and_then(|v| v.as_str()).unwrap_or("?");
                let _ = writeln!(out, "      [{category}] {a_file} vs {b_file}");
            }
        }
    }

    out
}

fn format_commit(commit: &str) -> &str {
    if commit.is_empty() {
        "(none)"
    } else if commit.len() > 8 {
        &commit[..8]
    } else {
        commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_status_with_full_data() {
        let data = serde_json::json!({
            "workspace_count": 3,
            "analysis_count": 2,
            "base_commit": "abc123def456",
        });
        let output = format_status_output(&data);
        assert!(output.contains("Workspaces:  3"));
        assert!(output.contains("Analyses:    2"));
        assert!(output.contains("abc123de"));
        // Should truncate to 8 chars
        assert!(!output.contains("abc123def456"));
    }

    #[test]
    fn format_status_with_empty_commit() {
        let data = serde_json::json!({
            "workspace_count": 0,
            "analysis_count": 0,
            "base_commit": "",
        });
        let output = format_status_output(&data);
        assert!(output.contains("(none)"));
    }

    #[test]
    fn format_status_with_missing_fields() {
        let data = serde_json::json!({});
        let output = format_status_output(&data);
        assert!(output.contains("Workspaces:  0"));
        assert!(output.contains("Analyses:    0"));
        assert!(output.contains("(none)"));
    }

    #[test]
    fn format_commit_truncates_long_hash() {
        assert_eq!(format_commit("abc123def456"), "abc123de");
    }

    #[test]
    fn format_commit_shows_short_hash_as_is() {
        assert_eq!(format_commit("abc123"), "abc123");
    }

    #[test]
    fn format_commit_shows_none_for_empty() {
        assert_eq!(format_commit(""), "(none)");
    }

    #[test]
    fn build_status_json_includes_expected_top_level_keys() {
        let status = serde_json::json!({
            "workspace_count": 2,
            "analysis_count": 1,
            "base_commit": "abc123def456",
        });
        let workspaces = serde_json::json!([
            {"id": "ws-1", "name": "main"},
            {"id": "ws-2", "name": "feature/auth"},
        ]);
        let analyses = serde_json::json!([
            {"workspace_a": "ws-1", "workspace_b": "ws-2", "score": "Yellow"}
        ]);

        let merged = build_status_json(&status, &workspaces, &analyses);

        assert_eq!(
            merged.get("workspace_count").and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(
            merged.get("analysis_count").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            merged.get("base_commit").and_then(|v| v.as_str()),
            Some("abc123def456")
        );
        assert!(merged.get("workspaces").is_some_and(|v| v.is_array()));
        assert!(merged.get("analyses").is_some_and(|v| v.is_array()));
    }

    #[test]
    fn build_status_json_uses_array_lengths_when_counts_missing() {
        let status = serde_json::json!({});
        let workspaces = serde_json::json!([
            {"id": "ws-1", "name": "main"},
            {"id": "ws-2", "name": "feature/auth"},
            {"id": "ws-3", "name": "feature/payments"},
        ]);
        let analyses = serde_json::json!([
            {"workspace_a": "ws-1", "workspace_b": "ws-2", "score": "Green"},
            {"workspace_a": "ws-2", "workspace_b": "ws-3", "score": "Red"},
        ]);

        let merged = build_status_json(&status, &workspaces, &analyses);

        assert_eq!(
            merged.get("workspace_count").and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(
            merged.get("analysis_count").and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(merged.get("base_commit").and_then(|v| v.as_str()), Some(""));
        assert!(merged.get("workspaces").is_some_and(|v| v.is_array()));
        assert!(merged.get("analyses").is_some_and(|v| v.is_array()));
    }

    #[test]
    fn format_status_with_invalid_field_types_uses_defaults() {
        let data = serde_json::json!({
            "workspace_count": "3",
            "analysis_count": {"n": 2},
            "base_commit": 12345,
        });
        let output = format_status_output(&data);
        assert!(output.contains("Workspaces:  0"));
        assert!(output.contains("Analyses:    0"));
        assert!(output.contains("Base commit: (none)"));
    }

    #[test]
    fn format_status_output_is_deterministic_for_same_input() {
        let data = serde_json::json!({
            "workspace_count": 5,
            "analysis_count": 4,
            "base_commit": "deadbeefcafebabe",
            "unexpected": "ignored",
        });
        let first = format_status_output(&data);
        let second = format_status_output(&data);
        assert_eq!(first, second);
    }

    #[test]
    fn format_commit_keeps_exactly_eight_chars() {
        assert_eq!(format_commit("deadbeef"), "deadbeef");
    }

    #[test]
    #[should_panic]
    fn format_commit_panics_when_truncating_unicode_mid_codepoint() {
        let _ = format_commit("你好你好你好");
    }

    #[test]
    fn format_smart_status_all_clean() {
        let data = serde_json::json!({
            "workspace_count": 3,
            "analysis_count": 3,
            "base_commit": "abc123def456",
        });
        let workspaces = serde_json::json!([
            {"name": "main", "id": "id-1", "branch": "refs/heads/main"},
            {"name": "auth-refactor", "id": "id-2", "branch": "refs/heads/auth-refactor"},
            {"name": "payment-fix", "id": "id-3", "branch": "refs/heads/payment-fix"},
        ]);
        let analyses = serde_json::json!([]);
        let output = format_smart_status(&data, &workspaces, &analyses);
        assert!(output.contains("3 worktrees"));
        assert!(output.contains("clean"));
    }

    #[test]
    fn format_smart_status_with_conflicts() {
        let data = serde_json::json!({
            "workspace_count": 2,
            "analysis_count": 1,
            "base_commit": "abc123def456",
        });
        let workspaces = serde_json::json!([
            {"name": "feature/auth", "id": "id-1", "branch": "refs/heads/feature/auth"},
            {"name": "feature/payment", "id": "id-2", "branch": "refs/heads/feature/payment"},
        ]);
        let analyses = serde_json::json!([{
            "workspace_a": "id-1",
            "workspace_b": "id-2",
            "score": "Red",
            "overlaps": [{"Symbol": {"path": "src/auth.ts", "symbol_name": "updateUser", "a_modification": "changed", "b_modification": "also changed"}}],
        }]);
        let output = format_smart_status(&data, &workspaces, &analyses);
        assert!(output.contains("1 conflict(s)"));
        assert!(output.contains("[Red] feature/auth <-> feature/payment"));
        assert!(output.contains("Both branches modify the same functions:"));
        assert!(output.contains("updateUser() in src/auth.ts"));
    }

    #[test]
    fn format_smart_status_resolves_ids_to_names() {
        let data = serde_json::json!({"workspace_count": 2, "base_commit": ""});
        let workspaces = serde_json::json!([
            {"name": "main", "id": "uuid-aaa", "branch": "refs/heads/main"},
            {"name": "feature/auth", "id": "uuid-bbb", "branch": "refs/heads/feature/auth"},
        ]);
        let analyses = serde_json::json!([{
            "workspace_a": "uuid-aaa",
            "workspace_b": "uuid-bbb",
            "score": "Yellow",
            "overlaps": [{"File": {"path": "src/shared.ts", "a_change": "Modified", "b_change": "Modified"}}],
        }]);
        let output = format_smart_status(&data, &workspaces, &analyses);
        assert!(output.contains("main <-> feature/auth"));
        assert!(!output.contains("uuid-aaa"));
        assert!(!output.contains("uuid-bbb"));
    }

    #[test]
    fn format_overlaps_grouped_separates_by_type() {
        let overlaps = vec![
            serde_json::json!({"File": {"path": "src/auth.ts"}}),
            serde_json::json!({"Symbol": {"path": "src/auth.ts", "symbol_name": "login"}}),
            serde_json::json!({"File": {"path": "src/utils.ts"}}),
            serde_json::json!({"Dependency": {"changed_file": "src/db.ts", "affected_file": "src/auth.ts"}}),
        ];
        let output = format_overlaps_grouped(&overlaps);

        // Files grouped together
        assert!(output.contains("Both branches edit the same files:"));
        assert!(output.contains("      src/auth.ts\n"));
        assert!(output.contains("      src/utils.ts\n"));

        // Symbols in their own section
        assert!(output.contains("Both branches modify the same functions:"));
        assert!(output.contains("      login() in src/auth.ts\n"));

        // Deps in their own section
        assert!(output.contains("One branch's changes affect the other's imports:"));
        assert!(output.contains("src/db.ts"));
    }

    #[test]
    fn format_overlaps_grouped_omits_empty_sections() {
        let overlaps = vec![
            serde_json::json!({"Hunk": {"path": "a.ts", "a_range": {"start": 10, "end": 20}}}),
        ];
        let output = format_overlaps_grouped(&overlaps);
        assert!(output.contains("Both branches change the same lines:"));
        assert!(output.contains("a.ts:10-20"));
        assert!(!output.contains("same files"));
        assert!(!output.contains("same functions"));
    }
}
