use crate::client::DaemonClient;
use crate::commands::CommandError;
use colored::Colorize;

/// Execute the `status` command, showing a workspace overview.
pub async fn execute(client: &DaemonClient, json: bool) -> Result<(), CommandError> {
    let response = client.status().await?;

    if !response.ok {
        let message = response.error.unwrap_or_else(|| "unknown error".to_string());
        return Err(CommandError::DaemonError(message));
    }

    let data = response.data.unwrap_or_default();

    if json {
        println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
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
    println!(
        "  Base commit: {}",
        format_commit(base_commit)
    );

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
    out.push_str(&format!(
        "  Base commit: {}\n",
        format_commit(base_commit)
    ));
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
}
