use std::path::PathBuf;

use crate::client::DaemonClient;

/// Git repository context resolved via `gix`.
#[derive(Debug, Clone)]
pub struct GitContext {
    /// The top-level directory of the repository (main worktree root).
    pub toplevel: PathBuf,
    /// The shared .git directory (common across all worktrees).
    pub common_dir: PathBuf,
}

/// A discovered worktree.
#[derive(Debug, Clone)]
pub struct DiscoveredWorktree {
    pub path: PathBuf,
    pub head: String,
    pub branch: Option<String>,
    pub name: String,
}

/// Resolve the git repository context using `gix::discover`.
pub fn resolve_git_context() -> Result<GitContext, String> {
    let repo = gix::discover(".").map_err(|e| format!("failed to discover git repository: {e}"))?;
    repo_to_git_context(&repo)
}

fn repo_to_git_context(repo: &gix::Repository) -> Result<GitContext, String> {
    let toplevel = repo
        .workdir()
        .ok_or("bare repository — no worktree found")?
        .to_path_buf();
    let common_dir = repo.common_dir().to_path_buf();

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
    if let Err(e) = add_to_git_exclude(ctx) {
        // Non-fatal: log warning, continue
        eprintln!("warning: could not update git exclude: {e}");
    }

    Ok(grove_dir)
}

fn add_to_git_exclude(ctx: &GitContext) -> Result<(), String> {
    let exclude_path = ctx.common_dir.join("info").join("exclude");

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

/// Discover all worktrees via `gix`.
pub fn discover_worktrees() -> Result<Vec<DiscoveredWorktree>, String> {
    let repo = gix::discover(".").map_err(|e| format!("failed to discover git repository: {e}"))?;

    let mut worktrees = Vec::new();

    // Main worktree
    if let Some(wt) = worktree_from_repo(&repo) {
        worktrees.push(wt);
    }

    // Linked worktrees
    let proxies = repo
        .worktrees()
        .map_err(|e| format!("failed to list worktrees: {e}"))?;
    for proxy in proxies {
        match proxy.into_repo_with_possibly_inaccessible_worktree() {
            Ok(linked_repo) => {
                if let Some(wt) = worktree_from_repo(&linked_repo) {
                    worktrees.push(wt);
                }
            }
            Err(e) => {
                eprintln!("warning: could not open linked worktree: {e}");
            }
        }
    }

    Ok(worktrees)
}

fn worktree_from_repo(repo: &gix::Repository) -> Option<DiscoveredWorktree> {
    let path = repo.workdir()?.to_path_buf();
    let head_ref = repo.head().ok()?;
    let head = head_ref
        .id()
        .map(|id| id.to_hex().to_string())
        .unwrap_or_default();
    let branch = head_ref
        .referent_name()
        .map(|name| name.as_bstr().to_string());
    let name = derive_name(&path, branch.as_deref());

    Some(DiscoveredWorktree {
        path,
        head,
        branch,
        name,
    })
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

#[cfg(test)]
mod tests {
    use super::*;

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
