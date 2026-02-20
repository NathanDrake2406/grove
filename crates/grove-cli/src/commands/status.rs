use crate::client::DaemonClient;
use crate::commands::CommandError;

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

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&status_data).unwrap_or_default()
        );
        return Ok(());
    }

    // Fetch workspaces and analyses for the full picture.
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

    println!("{}", format_smart_status(&status_data, &workspaces, &analyses));
    Ok(())
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
    out.push_str(&format!("  Workspaces:  {workspace_count}\n"));
    out.push_str(&format!("  Analyses:    {analysis_count}\n"));
    out.push_str(&format!("  Base commit: {}\n", format_commit(base_commit)));
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
    out.push_str(&format!(
        "  {} worktrees  |  base: {}\n\n",
        workspace_count,
        format_commit(base_commit)
    ));

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
                out.push_str(&format!("  {name}\n"));
            } else {
                out.push_str(&format!("  {name}  ({branch})\n"));
            }
        }
        out.push('\n');
    }

    // Separate conflicts from clean pairs.
    let conflict_pairs: Vec<_> = analyses
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|a| {
                    let score = a.get("score").and_then(|v| v.as_str()).unwrap_or("Green");
                    score != "Green"
                })
                .collect()
        })
        .unwrap_or_default();

    if conflict_pairs.is_empty() {
        out.push_str("  All worktrees clean \u{2014} no conflicts detected.\n");
        return out;
    }

    out.push_str(&format!("  {} conflict(s):\n\n", conflict_pairs.len()));

    for analysis in &conflict_pairs {
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
        let name_a = id_to_name
            .get(ws_a_id)
            .map(|s| s.as_str())
            .unwrap_or(ws_a_id);
        let name_b = id_to_name
            .get(ws_b_id)
            .map(|s| s.as_str())
            .unwrap_or(ws_b_id);
        let overlaps = analysis
            .get("overlaps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        out.push_str(&format!("  [{score}] {name_a} <-> {name_b}\n\n"));
        out.push_str(&format_overlaps_grouped(&overlaps));
        out.push('\n');
    }

    out
}

/// Build a map from workspace ID to workspace name.
fn build_id_name_map(workspaces: &serde_json::Value) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Some(arr) = workspaces.as_array() {
        for ws in arr {
            if let (Some(id), Some(name)) = (
                ws.get("id").and_then(|v| v.as_str()),
                ws.get("name").and_then(|v| v.as_str()),
            ) {
                map.insert(id.to_string(), name.to_string());
            }
        }
    }
    map
}

/// Group overlaps by type and format with section headers.
fn format_overlaps_grouped(overlaps: &[serde_json::Value]) -> String {
    let mut files: Vec<String> = Vec::new();
    let mut hunks: Vec<String> = Vec::new();
    let mut symbols: Vec<String> = Vec::new();
    let mut deps: Vec<String> = Vec::new();
    let mut schemas: Vec<String> = Vec::new();

    for overlap in overlaps {
        if let Some(data) = overlap.get("File") {
            let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            files.push(path.to_string());
        } else if let Some(data) = overlap.get("Hunk") {
            let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let a_start = data.get("a_range").and_then(|v| v.get("start")).and_then(|v| v.as_u64());
            let a_end = data.get("a_range").and_then(|v| v.get("end")).and_then(|v| v.as_u64());
            match (a_start, a_end) {
                (Some(s), Some(e)) => hunks.push(format!("{path}:{s}-{e}")),
                _ => hunks.push(path.to_string()),
            }
        } else if let Some(data) = overlap.get("Symbol") {
            let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
            let name = data.get("symbol_name").and_then(|v| v.as_str()).unwrap_or("?");
            symbols.push(format!("{name}() in {path}"));
        } else if let Some(data) = overlap.get("Dependency") {
            let changed = data.get("changed_file").and_then(|v| v.as_str()).unwrap_or("?");
            let affected = data.get("affected_file").and_then(|v| v.as_str()).unwrap_or("?");
            deps.push(format!("{changed} \u{2192} {affected}"));
        } else if let Some(data) = overlap.get("Schema") {
            let cat = data.get("category").and_then(|v| v.as_str()).unwrap_or("?");
            let a_file = data.get("a_file").and_then(|v| v.as_str()).unwrap_or("?");
            let b_file = data.get("b_file").and_then(|v| v.as_str()).unwrap_or("?");
            schemas.push(format!("[{cat}] {a_file} vs {b_file}"));
        }
    }

    let mut out = String::new();

    if !files.is_empty() {
        out.push_str("    Both branches edit the same files:\n");
        for f in &files {
            out.push_str(&format!("      {f}\n"));
        }
    }

    if !hunks.is_empty() {
        out.push_str("    Both branches change the same lines:\n");
        for h in &hunks {
            out.push_str(&format!("      {h}\n"));
        }
    }

    if !symbols.is_empty() {
        out.push_str("    Both branches modify the same functions:\n");
        for s in &symbols {
            out.push_str(&format!("      {s}\n"));
        }
    }

    if !deps.is_empty() {
        out.push_str("    One branch's changes affect the other's imports:\n");
        for d in &deps {
            out.push_str(&format!("      {d}\n"));
        }
    }

    if !schemas.is_empty() {
        out.push_str("    Both branches touch shared config/schemas:\n");
        for s in &schemas {
            out.push_str(&format!("      {s}\n"));
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
