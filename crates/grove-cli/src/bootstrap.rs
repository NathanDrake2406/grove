use std::path::{Path, PathBuf};

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
    resolve_git_context_from(Path::new("."))
}

fn resolve_git_context_from(start: &Path) -> Result<GitContext, String> {
    let repo =
        gix::discover(start).map_err(|e| format!("failed to discover git repository: {e}"))?;
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
    infer_repo_root_from_common_dir(&ctx.common_dir)
        .unwrap_or_else(|| ctx.toplevel.clone())
        .join(".grove")
}

fn infer_repo_root_from_common_dir(common_dir: &Path) -> Option<PathBuf> {
    // Resolve any .git-related shape to the repo root:
    //   <repo>/.git
    //   <repo>/.git/worktrees
    //   <repo>/.git/worktrees/<name>
    for ancestor in common_dir.ancestors() {
        if ancestor.file_name().is_some_and(|name| name == ".git") {
            return ancestor.parent().map(Path::to_path_buf);
        }
    }

    // Fallback for bare-style common dirs (e.g. /path/repo.git).
    common_dir.parent().map(Path::to_path_buf)
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
    discover_worktrees_from(Path::new("."))
}

fn discover_worktrees_from(start: &Path) -> Result<Vec<DiscoveredWorktree>, String> {
    let repo =
        gix::discover(start).map_err(|e| format!("failed to discover git repository: {e}"))?;

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
    ensure_daemon_with(grove_dir, 30, 100, spawn_daemon).await
}

async fn ensure_daemon_with<F>(
    grove_dir: &std::path::Path,
    max_attempts: usize,
    poll_interval_ms: u64,
    spawn: F,
) -> Result<DaemonClient, String>
where
    F: Fn(&std::path::Path) -> Result<(), String>,
{
    let socket_path = grove_dir.join("daemon.sock");
    let client = DaemonClient::new(&socket_path);

    // Try socket ping first (source of truth for liveness)
    if client.status().await.is_ok() {
        return Ok(client);
    }

    // Daemon not responding -- spawn it
    spawn(grove_dir)?;

    // Poll for readiness
    for _ in 0..max_attempts {
        tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
        if client.status().await.is_ok() {
            return Ok(client);
        }
    }

    Err("daemon failed to start within timeout window".to_string())
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
    use std::process::Command;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .expect("git command should run");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn spawn_status_server(socket_path: PathBuf, requests: usize) -> tokio::task::JoinHandle<()> {
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("socket should bind");
        tokio::spawn(async move {
            for _ in 0..requests {
                let (stream, _) = listener.accept().await.expect("accept should succeed");
                let mut reader = BufReader::new(stream);
                let mut request_line = String::new();
                let _ = reader
                    .read_line(&mut request_line)
                    .await
                    .expect("request line should read");
                let mut stream = reader.into_inner();
                stream
                    .write_all(br#"{"ok":true,"data":{"status":"ok"}}"#)
                    .await
                    .expect("response should write");
                stream.write_all(b"\n").await.expect("newline should write");
            }
        })
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

    #[test]
    fn grove_dir_works_for_linked_worktree_common_dir() {
        let ctx = GitContext {
            toplevel: PathBuf::from("/home/user/myproject/.worktrees/feature-x"),
            common_dir: PathBuf::from("/home/user/myproject/.git/worktrees/feature-x"),
        };
        assert_eq!(
            grove_dir_from_context(&ctx),
            PathBuf::from("/home/user/myproject/.grove")
        );
    }

    #[test]
    fn infer_repo_root_from_common_dir_finds_git_ancestor() {
        let common = PathBuf::from("/home/user/repo/.git/worktrees/feature-a");
        assert_eq!(
            infer_repo_root_from_common_dir(&common),
            Some(PathBuf::from("/home/user/repo"))
        );
    }

    #[test]
    fn infer_repo_root_from_common_dir_uses_parent_for_bare_style_path() {
        let common = PathBuf::from("/home/user/repo.git");
        assert_eq!(
            infer_repo_root_from_common_dir(&common),
            Some(PathBuf::from("/home/user"))
        );
    }

    #[test]
    fn derive_name_prefers_branch_and_strips_refs_heads_prefix() {
        let path = PathBuf::from("/tmp/repo/worktree-a");
        assert_eq!(
            derive_name(&path, Some("refs/heads/feature/tight-tests")),
            "feature/tight-tests"
        );
        assert_eq!(
            derive_name(&path, Some("feature/no-prefix")),
            "feature/no-prefix"
        );
    }

    #[test]
    fn derive_name_falls_back_to_path_basename_or_unknown() {
        let path = PathBuf::from("/tmp/repo/worktree-a");
        assert_eq!(derive_name(&path, None), "worktree-a");

        let root_like = PathBuf::from("/");
        assert_eq!(derive_name(&root_like, None), "unknown");
    }

    #[test]
    fn add_to_git_exclude_appends_entry_once_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let common_dir = tmp.path().join(".git");
        std::fs::create_dir_all(common_dir.join("info")).unwrap();

        let ctx = GitContext {
            toplevel: tmp.path().to_path_buf(),
            common_dir: common_dir.clone(),
        };

        add_to_git_exclude(&ctx).unwrap();
        add_to_git_exclude(&ctx).unwrap();

        let exclude = std::fs::read_to_string(common_dir.join("info").join("exclude")).unwrap();
        let grove_entries = exclude
            .lines()
            .filter(|line| line.trim() == ".grove/")
            .count();
        assert_eq!(grove_entries, 1);
    }

    #[test]
    fn add_to_git_exclude_preserves_existing_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let common_dir = tmp.path().join(".git");
        let info_dir = common_dir.join("info");
        std::fs::create_dir_all(&info_dir).unwrap();
        let exclude_path = info_dir.join("exclude");
        std::fs::write(&exclude_path, "target/\nnode_modules/\n").unwrap();

        let ctx = GitContext {
            toplevel: tmp.path().to_path_buf(),
            common_dir: common_dir.clone(),
        };

        add_to_git_exclude(&ctx).unwrap();

        let exclude = std::fs::read_to_string(exclude_path).unwrap();
        assert!(exclude.contains("target/"));
        assert!(exclude.contains("node_modules/"));
        assert!(exclude.lines().any(|line| line.trim() == ".grove/"));
    }

    #[test]
    fn ensure_grove_dir_creates_directory_and_updates_exclude() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        let common_dir = repo_root.join(".git");
        std::fs::create_dir_all(common_dir.join("info")).unwrap();
        std::fs::create_dir_all(&repo_root).unwrap();

        let ctx = GitContext {
            toplevel: repo_root.clone(),
            common_dir: common_dir.clone(),
        };

        let grove_dir = ensure_grove_dir(&ctx).unwrap();
        assert_eq!(grove_dir, repo_root.join(".grove"));
        assert!(grove_dir.is_dir());

        let exclude = std::fs::read_to_string(common_dir.join("info").join("exclude")).unwrap();
        assert!(exclude.lines().any(|line| line.trim() == ".grove/"));
    }

    #[test]
    fn resolve_git_context_from_errors_outside_repo() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_git_context_from(dir.path()).unwrap_err();
        assert!(err.contains("failed to discover git repository"));
    }

    #[test]
    fn discover_worktrees_from_finds_main_and_linked_worktrees() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "grove@example.com"]);
        run_git(&repo, &["config", "user.name", "Grove Tests"]);
        std::fs::write(repo.join("README.md"), "test\n").unwrap();
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "init"]);

        let wt_b = temp.path().join("wt-b");
        run_git(
            &repo,
            &[
                "worktree",
                "add",
                wt_b.to_str().expect("utf8 path"),
                "-b",
                "feat/b",
                "main",
            ],
        );

        let discovered = discover_worktrees_from(&repo).unwrap();
        assert!(discovered.len() >= 2);
        assert!(discovered.iter().any(|w| w.path.ends_with("repo")));
        assert!(discovered.iter().any(|w| w.path.ends_with("wt-b")));
        assert!(discovered.iter().any(|w| w.name.contains("main")));
        assert!(discovered.iter().any(|w| w.name.contains("feat/b")));
    }

    #[tokio::test]
    async fn ensure_daemon_returns_when_socket_already_responding() {
        let temp = tempfile::tempdir().unwrap();
        let grove_dir = temp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();
        let socket = grove_dir.join("daemon.sock");
        let server = spawn_status_server(socket.clone(), 1);

        let client = ensure_daemon(&grove_dir).await.unwrap();
        assert_eq!(client.socket_path(), socket.as_path());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ensure_daemon_with_spawns_then_waits_until_ready() {
        let temp = tempfile::tempdir().unwrap();
        let grove_dir = temp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();
        let socket = grove_dir.join("daemon.sock");
        let spawn_calls = Arc::new(AtomicUsize::new(0));

        let calls = Arc::clone(&spawn_calls);
        let result = ensure_daemon_with(&grove_dir, 20, 10, move |_dir| {
            calls.fetch_add(1, Ordering::SeqCst);
            let socket_path = socket.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("runtime should create");
                rt.block_on(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                    let server = spawn_status_server(socket_path, 1);
                    server.await.expect("server should finish");
                });
            });
            Ok(())
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(spawn_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ensure_daemon_with_propagates_spawn_errors() {
        let temp = tempfile::tempdir().unwrap();
        let grove_dir = temp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let err = ensure_daemon_with(&grove_dir, 2, 1, |_dir| Err("spawn failed".to_string()))
            .await
            .err()
            .expect("spawn failure should return an error");
        assert!(err.contains("spawn failed"));
    }

    #[tokio::test]
    async fn ensure_daemon_with_times_out_when_daemon_never_comes_up() {
        let temp = tempfile::tempdir().unwrap();
        let grove_dir = temp.path().join(".grove");
        std::fs::create_dir_all(&grove_dir).unwrap();

        let err = ensure_daemon_with(&grove_dir, 2, 1, |_dir| Ok(()))
            .await
            .err()
            .expect("timeout should return an error");
        assert!(err.contains("failed to start"));
    }
}
