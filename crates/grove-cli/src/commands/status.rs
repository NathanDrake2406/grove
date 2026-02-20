use crate::client::DaemonClient;
use crate::commands::CommandError;
use colored::Colorize;

/// Execute the `status` command, showing a workspace overview.
pub async fn execute(client: &DaemonClient, json: bool) -> Result<(), CommandError> {
    let response = client.status().await?;

    if !response.ok {
        let message = response
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(CommandError::DaemonError(message));
    }

    let data = response.data.unwrap_or_default();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
        return Ok(());
    }

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

    println!("{}", "Grove Status".bold());
    println!("{}", "─".repeat(40));
    println!("  Workspaces:  {}", workspace_count);
    println!("  Analyses:    {}", analysis_count);
    println!("  Base commit: {}", format_commit(base_commit));

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

    let mut out = String::new();
    out.push_str("Grove Status\n");
    out.push_str(&"\u{2500}".repeat(50));
    out.push('\n');
    out.push_str(&format!(
        "  {} worktrees  |  base: {}\n",
        workspace_count,
        format_commit(base_commit)
    ));
    out.push('\n');

    // List worktrees
    if let Some(ws_array) = workspaces.as_array() {
        out.push_str("  Worktrees:\n");
        for ws in ws_array {
            let name = ws.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            out.push_str(&format!("    - {name}\n"));
        }
        out.push('\n');
    }

    // Show conflicts or "clean"
    let has_conflicts = analyses
        .as_array()
        .map(|arr| {
            arr.iter().any(|a| {
                let score = a.get("score").and_then(|v| v.as_str()).unwrap_or("Green");
                score != "Green"
            })
        })
        .unwrap_or(false);

    if has_conflicts {
        out.push_str("  Conflicts:\n");
        if let Some(arr) = analyses.as_array() {
            for analysis in arr {
                let score = analysis
                    .get("score")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                if score == "Green" {
                    continue;
                }
                let ws_a = analysis
                    .get("workspace_a")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let ws_b = analysis
                    .get("workspace_b")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let overlap_count = analysis
                    .get("overlaps")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                out.push_str(&format!(
                    "    [{score}] {ws_a} <-> {ws_b} ({overlap_count} overlaps)\n"
                ));
            }
        }
    } else {
        out.push_str("  All worktrees clean \u{2014} no conflicts detected.\n");
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
            {"name": "main", "id": "id-1"},
            {"name": "auth-refactor", "id": "id-2"},
            {"name": "payment-fix", "id": "id-3"},
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
            {"name": "auth", "id": "id-1"},
            {"name": "payment", "id": "id-2"},
        ]);
        let analyses = serde_json::json!([{
            "workspace_a": "id-1",
            "workspace_b": "id-2",
            "score": "Red",
            "overlaps": [{"Symbol": {"path": "src/auth.ts", "symbol_name": "updateUser", "a_modification": "changed", "b_modification": "also changed"}}],
        }]);
        let output = format_smart_status(&data, &workspaces, &analyses);
        assert!(output.contains("Conflicts"));
    }
}
