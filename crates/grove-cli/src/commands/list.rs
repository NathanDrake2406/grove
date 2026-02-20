use crate::client::DaemonClient;
use crate::commands::CommandError;

/// Execute the `list` command, showing all tracked workspaces.
pub async fn execute(client: &DaemonClient, json: bool) -> Result<(), CommandError> {
    let response = client.list_workspaces().await?;

    if !response.ok {
        let message = response.error.unwrap_or_else(|| "unknown error".to_string());
        return Err(CommandError::DaemonError(message));
    }

    let data = response.data.unwrap_or_default();

    if json {
        println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
        return Ok(());
    }

    let workspaces = data.as_array().cloned().unwrap_or_default();

    if workspaces.is_empty() {
        println!("No workspaces tracked.");
        return Ok(());
    }

    println!("{}", format_workspace_table(&workspaces));
    Ok(())
}

/// Format a list of workspace JSON values as a plain-text table (extracted for testing).
pub fn format_workspace_table(workspaces: &[serde_json::Value]) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<38} {:<20} {:<30} {}\n",
        "ID", "NAME", "BRANCH", "PATH"
    ));
    out.push_str(&"─".repeat(100));
    out.push('\n');

    for ws in workspaces {
        let id = ws
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let name = ws
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unnamed)");
        let branch = ws
            .get("branch")
            .and_then(|v| v.as_str())
            .unwrap_or("(no branch)");
        let path = ws
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("(no path)");

        out.push_str(&format!(
            "{:<38} {:<20} {:<30} {}\n",
            truncate(id, 36),
            truncate(name, 18),
            truncate(branch, 28),
            path,
        ));
    }

    out.push_str(&format!("\n{} workspace(s)", workspaces.len()));
    out
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_table_with_workspaces() {
        let workspaces = vec![
            serde_json::json!({
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "name": "auth-refactor",
                "branch": "feat/auth-refactor",
                "path": "/worktrees/auth-refactor",
            }),
            serde_json::json!({
                "id": "660e8400-e29b-41d4-a716-446655440001",
                "name": "cache-layer",
                "branch": "feat/cache-layer",
                "path": "/worktrees/cache-layer",
            }),
        ];
        let output = format_workspace_table(&workspaces);

        assert!(output.contains("ID"));
        assert!(output.contains("NAME"));
        assert!(output.contains("BRANCH"));
        assert!(output.contains("PATH"));
        assert!(output.contains("auth-refactor"));
        assert!(output.contains("cache-layer"));
        assert!(output.contains("feat/auth-refactor"));
        assert!(output.contains("/worktrees/cache-layer"));
        assert!(output.contains("2 workspace(s)"));
    }

    #[test]
    fn format_table_with_empty_list() {
        let workspaces: Vec<serde_json::Value> = vec![];
        let output = format_workspace_table(&workspaces);

        assert!(output.contains("ID"));
        assert!(output.contains("0 workspace(s)"));
    }

    #[test]
    fn format_table_with_missing_fields() {
        let workspaces = vec![serde_json::json!({})];
        let output = format_workspace_table(&workspaces);

        assert!(output.contains("(unknown)"));
        assert!(output.contains("(unnamed)"));
        assert!(output.contains("(no branch)"));
        assert!(output.contains("(no path)"));
    }

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_long_string_with_ellipsis() {
        let result = truncate("a very long string indeed", 10);
        assert_eq!(result, "a very lo…");
        assert_eq!(result.chars().count(), 10);
    }

    #[test]
    fn truncate_exact_length_unchanged() {
        assert_eq!(truncate("exactly10!", 10), "exactly10!");
    }
}
