use std::path::PathBuf;

use crate::client::DaemonClient;

/// Git repository context resolved from `git rev-parse`.
#[derive(Debug, Clone)]
pub struct GitContext {
    /// The top-level directory of the repository (main worktree root).
    pub toplevel: PathBuf,
    /// The shared .git directory (common across all worktrees).
    pub common_dir: PathBuf,
}

/// A discovered worktree from `git worktree list --porcelain`.
#[derive(Debug, Clone)]
pub struct DiscoveredWorktree {
    pub path: PathBuf,
    pub head: String,
    pub branch: Option<String>,
    pub name: String,
}

/// Resolve the git repository context using `git rev-parse`.
pub fn resolve_git_context() -> Result<GitContext, String> {
    let toplevel = run_git(&["rev-parse", "--show-toplevel"])?;
    let common_dir = run_git(&["rev-parse", "--git-common-dir"])?;

    let toplevel = PathBuf::from(toplevel.trim());
    let common_dir_raw = common_dir.trim();

    // git rev-parse --git-common-dir returns a relative path when inside the repo
    let common_dir = if PathBuf::from(common_dir_raw).is_absolute() {
        PathBuf::from(common_dir_raw)
    } else {
        toplevel.join(common_dir_raw)
    };

    Ok(GitContext {
        toplevel,
        common_dir,
    })
}

/// Derive the canonical `.grove/` directory from git context.
pub fn grove_dir_from_context(ctx: &GitContext) -> PathBuf {
    ctx.common_dir
        .parent()
        .unwrap_or(&ctx.toplevel)
        .join(".grove")
}

/// Ensure `.grove/` directory exists and is excluded from git tracking.
pub fn ensure_grove_dir(ctx: &GitContext) -> Result<PathBuf, String> {
    let grove_dir = grove_dir_from_context(ctx);

    std::fs::create_dir_all(&grove_dir)
        .map_err(|e| format!("failed to create {}: {e}", grove_dir.display()))?;

    // Add .grove/ to git exclude (not .gitignore -- avoids diffs)
    if let Err(e) = add_to_git_exclude(&grove_dir) {
        // Non-fatal: log warning, continue
        eprintln!("warning: could not update git exclude: {e}");
    }

    Ok(grove_dir)
}

fn add_to_git_exclude(_grove_dir: &std::path::Path) -> Result<(), String> {
    let exclude_path_output = run_git(&["rev-parse", "--git-path", "info/exclude"])?;
    let exclude_path = PathBuf::from(exclude_path_output.trim());

    // Ensure parent directory exists
    if let Some(parent) = exclude_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create exclude dir: {e}"))?;
    }

    let entry = ".grove/";

    // Check if already present
    if let Ok(contents) = std::fs::read_to_string(&exclude_path)
        && contents.lines().any(|line| line.trim() == entry)
    {
        return Ok(());
    }

    // Append
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&exclude_path)
        .map_err(|e| format!("failed to open exclude file: {e}"))?;

    writeln!(file, "{entry}").map_err(|e| format!("failed to write to exclude file: {e}"))?;

    Ok(())
}

/// Discover all worktrees via `git worktree list --porcelain`.
pub fn discover_worktrees() -> Result<Vec<DiscoveredWorktree>, String> {
    let output = run_git(&["worktree", "list", "--porcelain"])?;
    Ok(parse_worktree_list(&output))
}

/// Parse `git worktree list --porcelain` output.
pub fn parse_worktree_list(output: &str) -> Vec<DiscoveredWorktree> {
    let mut worktrees = Vec::new();
    let mut path: Option<PathBuf> = None;
    let mut head: Option<String> = None;
    let mut branch: Option<String> = None;

    for line in output.lines() {
        if let Some(p) = line.strip_prefix("worktree ") {
            // Flush previous entry
            if let (Some(p), Some(h)) = (path.take(), head.take()) {
                let name = derive_name(&p, branch.as_deref());
                worktrees.push(DiscoveredWorktree {
                    path: p,
                    head: h,
                    branch: branch.take(),
                    name,
                });
            }
            path = Some(PathBuf::from(p));
            head = None;
            branch = None;
        } else if let Some(h) = line.strip_prefix("HEAD ") {
            head = Some(h.to_string());
        } else if let Some(b) = line.strip_prefix("branch ") {
            branch = Some(b.to_string());
        }
        // "detached" and blank lines are ignored
    }

    // Flush last entry
    if let (Some(p), Some(h)) = (path, head) {
        let name = derive_name(&p, branch.as_deref());
        worktrees.push(DiscoveredWorktree {
            path: p,
            head: h,
            branch,
            name,
        });
    }

    worktrees
}

/// Check if the daemon is running; start it if not.
/// Returns a connected `DaemonClient`.
pub async fn ensure_daemon(grove_dir: &std::path::Path) -> Result<DaemonClient, String> {
    let socket_path = grove_dir.join("daemon.sock");
    let client = DaemonClient::new(&socket_path);

    // Try socket ping first (source of truth for liveness)
    if client.status().await.is_ok() {
        return Ok(client);
    }

    // Daemon not responding -- spawn it
    spawn_daemon(grove_dir)?;

    // Poll for readiness
    let max_attempts = 30; // 3 seconds with 100ms intervals
    for _ in 0..max_attempts {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if client.status().await.is_ok() {
            return Ok(client);
        }
    }

    Err("daemon failed to start within 3 seconds".to_string())
}

fn spawn_daemon(_grove_dir: &std::path::Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find grove executable: {e}"))?;

    std::process::Command::new(exe)
        .args(["daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn daemon: {e}"))?;

    Ok(())
}

fn derive_name(path: &std::path::Path, branch: Option<&str>) -> String {
    match branch {
        Some(b) => b.strip_prefix("refs/heads/").unwrap_or(b).to_string(),
        None => path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

/// Full bootstrap: resolve git context → ensure .grove/ → ensure daemon → discover worktrees → sync.
/// Returns a connected `DaemonClient` ready for use.
pub async fn bootstrap() -> Result<(DaemonClient, std::path::PathBuf), String> {
    let ctx = resolve_git_context()?;
    let grove_dir = ensure_grove_dir(&ctx)?;
    let client = ensure_daemon(&grove_dir).await?;

    let worktrees = discover_worktrees()?;

    // Build the sync payload
    let worktree_params: Vec<serde_json::Value> = worktrees
        .iter()
        .map(|wt| {
            serde_json::json!({
                "name": wt.name,
                "path": wt.path.to_string_lossy(),
                "branch": wt.branch.as_deref().unwrap_or(""),
                "head": wt.head,
            })
        })
        .collect();

    let resp = client
        .sync_worktrees(serde_json::Value::Array(worktree_params))
        .await
        .map_err(|e| format!("sync_worktrees failed: {e}"))?;

    if !resp.ok {
        let msg = resp.error.unwrap_or_else(|| "unknown error".to_string());
        return Err(format!("sync_worktrees error: {msg}"));
    }

    Ok((client, grove_dir))
}

fn run_git(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("failed to run git: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {}", args.join(" "), stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_worktree_list_single_worktree() {
        let output = "\
worktree /home/user/myproject
HEAD abc123def456
branch refs/heads/main
";
        let result = parse_worktree_list(output);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, PathBuf::from("/home/user/myproject"));
        assert_eq!(result[0].head, "abc123def456");
        assert_eq!(result[0].branch.as_deref(), Some("refs/heads/main"));
        assert_eq!(result[0].name, "main");
    }

    #[test]
    fn parse_worktree_list_multiple_worktrees() {
        let output = "\
worktree /home/user/myproject
HEAD abc123
branch refs/heads/main

worktree /home/user/myproject-auth
HEAD def456
branch refs/heads/feat/auth-refactor

worktree /home/user/myproject-pay
HEAD 789abc
branch refs/heads/fix/payment
";
        let result = parse_worktree_list(output);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].name, "main");
        assert_eq!(result[1].name, "feat/auth-refactor");
        assert_eq!(result[2].name, "fix/payment");
    }

    #[test]
    fn parse_worktree_list_detached_head() {
        let output = "\
worktree /home/user/myproject-detached
HEAD abc123
detached
";
        let result = parse_worktree_list(output);
        assert_eq!(result.len(), 1);
        assert!(result[0].branch.is_none());
        // Falls back to directory basename
        assert_eq!(result[0].name, "myproject-detached");
    }

    #[test]
    fn parse_worktree_list_empty_output() {
        let result = parse_worktree_list("");
        assert!(result.is_empty());
    }

    #[test]
    fn grove_dir_is_sibling_of_common_dir() {
        let ctx = GitContext {
            toplevel: PathBuf::from("/home/user/myproject"),
            common_dir: PathBuf::from("/home/user/myproject/.git"),
        };
        assert_eq!(
            grove_dir_from_context(&ctx),
            PathBuf::from("/home/user/myproject/.grove")
        );
    }

    #[test]
    fn grove_dir_works_for_bare_style_common_dir() {
        let ctx = GitContext {
            toplevel: PathBuf::from("/home/user/myproject"),
            common_dir: PathBuf::from("/home/user/myproject.git"),
        };
        // Parent of /home/user/myproject.git is /home/user
        assert_eq!(
            grove_dir_from_context(&ctx),
            PathBuf::from("/home/user/.grove")
        );
    }
}
