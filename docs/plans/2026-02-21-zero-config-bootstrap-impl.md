# Zero-Config Bootstrap Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make `grove` (no args) auto-discover worktrees, start the daemon, sync state, and show a smart status view — zero manual setup.

**Architecture:** Add a `bootstrap` module to `grove-cli` that resolves git context, ensures `.grove/` exists in the shared git dir, ensures the daemon is running, and syncs worktrees via a new atomic `sync_worktrees` socket command. Update the `grove` binary entry point to call bootstrap before dispatching CLI commands. Update the status renderer for smart output.

**Tech Stack:** Rust, `std::process::Command` (for `git rev-parse`), UUID v5 (deterministic workspace IDs), existing `tokio`/`serde_json`/`clap` stack.

---

## Task 1: Add UUID v5 support to workspace dependencies

**Files:**
- Modify: `Cargo.toml:59` (workspace deps)
- Modify: `crates/grove-daemon/Cargo.toml:19`

**Step 1: Add v5 feature to uuid workspace dependency**

In `Cargo.toml` line 59, change:
```toml
uuid = { version = "1", features = ["v4", "serde"] }
```
to:
```toml
uuid = { version = "1", features = ["v4", "v5", "serde"] }
```

**Step 2: Verify build**

Run: `cargo build`
Expected: compiles cleanly

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore: add uuid v5 feature for deterministic workspace IDs"
```

---

## Task 2: Make RegisterWorkspace idempotent and RemoveWorkspace tolerant

**Files:**
- Modify: `crates/grove-daemon/src/state.rs:380-423`
- Test: `crates/grove-daemon/src/state.rs` (inline tests)

**Step 1: Write failing tests**

Add to the `#[cfg(test)] mod tests` block in `crates/grove-daemon/src/state.rs`:

```rust
#[tokio::test]
async fn register_existing_workspace_is_idempotent() {
    let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

    let ws = make_workspace("idempotent");
    let ws_id = ws.id;

    // Register first time
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(StateMessage::RegisterWorkspace {
        workspace: ws.clone(),
        reply: reply_tx,
    }).await.unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Register same workspace again — should succeed, not error
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(StateMessage::RegisterWorkspace {
        workspace: ws,
        reply: reply_tx,
    }).await.unwrap();
    assert!(reply_rx.await.unwrap().is_ok());

    // Should still have exactly 1 workspace
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(StateMessage::Query {
        request: QueryRequest::GetStatus,
        reply: reply_tx,
    }).await.unwrap();
    match reply_rx.await.unwrap() {
        QueryResponse::Status { workspace_count, .. } => assert_eq!(workspace_count, 1),
        other => panic!("unexpected: {other:?}"),
    }

    tx.send(StateMessage::Shutdown).await.unwrap();
    handle.await.unwrap();
}

#[tokio::test]
async fn remove_nonexistent_workspace_is_noop() {
    let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(StateMessage::RemoveWorkspace {
        workspace_id: Uuid::new_v4(),
        reply: reply_tx,
    }).await.unwrap();
    // Should succeed (no-op), not error
    assert!(reply_rx.await.unwrap().is_ok());

    tx.send(StateMessage::Shutdown).await.unwrap();
    handle.await.unwrap();
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p grove-daemon register_existing_workspace_is_idempotent remove_nonexistent_workspace_is_noop -- --nocapture`
Expected: both FAIL

**Step 3: Fix `handle_register_workspace`**

In `crates/grove-daemon/src/state.rs`, replace `handle_register_workspace` (lines 380-400):

```rust
fn handle_register_workspace(&mut self, workspace: Workspace) -> Result<(), String> {
    let id = workspace.id;

    // If already registered (same ID), update metadata and return Ok.
    if self.workspaces.contains_key(&id) {
        info!(workspace_id = %id, name = %workspace.name, "workspace already registered, updating");
        if let Some(ref db) = self.db
            && let Err(e) = db.save_workspace(&workspace)
        {
            error!(error = %e, "failed to persist workspace update");
            return Err(format!("persistence error: {e}"));
        }
        self.workspaces.insert(id, workspace);
        return Ok(());
    }

    if self.workspaces.len() >= self.config.max_worktrees {
        return Err(format!(
            "maximum worktree limit ({}) reached",
            self.config.max_worktrees
        ));
    }

    info!(workspace_id = %id, name = %workspace.name, "registering workspace");

    if let Some(ref db) = self.db
        && let Err(e) = db.save_workspace(&workspace)
    {
        error!(error = %e, "failed to persist workspace");
        return Err(format!("persistence error: {e}"));
    }

    self.workspaces.insert(id, workspace);
    Ok(())
}
```

**Step 4: Fix `handle_remove_workspace`**

In `crates/grove-daemon/src/state.rs`, replace `handle_remove_workspace` (lines 402-423):

```rust
fn handle_remove_workspace(&mut self, workspace_id: WorkspaceId) -> Result<(), String> {
    if self.workspaces.remove(&workspace_id).is_none() {
        // Idempotent: removing a non-existent workspace is a no-op.
        debug!(workspace_id = %workspace_id, "remove requested for unknown workspace, ignoring");
        return Ok(());
    }

    info!(workspace_id = %workspace_id, "removing workspace");

    self.workspace_overlays.remove(&workspace_id);
    self.dirty_workspaces.retain(|id| *id != workspace_id);

    // Remove all pair analyses involving this workspace
    self.pair_analyses
        .retain(|(a, b), _| *a != workspace_id && *b != workspace_id);

    if let Some(ref db) = self.db
        && let Err(e) = db.delete_workspace(workspace_id)
    {
        error!(error = %e, "failed to delete workspace from db");
    }

    Ok(())
}
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p grove-daemon register_existing_workspace_is_idempotent remove_nonexistent_workspace_is_noop -- --nocapture`
Expected: PASS

**Step 6: Run full daemon test suite**

Run: `cargo test -p grove-daemon`
Expected: all pass (existing tests still work with idempotent semantics)

**Step 7: Commit**

```bash
git add crates/grove-daemon/src/state.rs
git commit -m "fix: make register/remove workspace idempotent"
```

---

## Task 3: Add `SyncWorktrees` message to the state actor

**Files:**
- Modify: `crates/grove-daemon/src/state.rs`
- Test: `crates/grove-daemon/src/state.rs` (inline tests)

**Step 1: Write failing test**

Add to tests in `crates/grove-daemon/src/state.rs`:

```rust
#[tokio::test]
async fn sync_worktrees_adds_new_and_removes_stale() {
    let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

    // Register two workspaces
    let ws_a = make_workspace("alpha");
    let ws_b = make_workspace("beta");
    let id_a = ws_a.id;
    let id_b = ws_b.id;
    for ws in [ws_a.clone(), ws_b.clone()] {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace { workspace: ws, reply: reply_tx }).await.unwrap();
        reply_rx.await.unwrap().unwrap();
    }

    // Sync with only alpha + a new gamma — beta should be removed
    let ws_gamma = make_workspace("gamma");
    let id_gamma = ws_gamma.id;
    let desired = vec![ws_a, ws_gamma];

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(StateMessage::SyncWorktrees { desired, reply: reply_tx }).await.unwrap();
    let result = reply_rx.await.unwrap().unwrap();

    assert!(result.added.contains(&id_gamma));
    assert!(result.removed.contains(&id_b));
    assert!(result.unchanged.contains(&id_a));

    // Verify state: 2 workspaces (alpha + gamma)
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(StateMessage::Query { request: QueryRequest::GetStatus, reply: reply_tx }).await.unwrap();
    match reply_rx.await.unwrap() {
        QueryResponse::Status { workspace_count, .. } => assert_eq!(workspace_count, 2),
        other => panic!("unexpected: {other:?}"),
    }

    tx.send(StateMessage::Shutdown).await.unwrap();
    handle.await.unwrap();
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p grove-daemon sync_worktrees_adds_new_and_removes_stale -- --nocapture`
Expected: FAIL (compile error — `SyncWorktrees` variant doesn't exist yet)

**Step 3: Add `SyncResult` struct and `SyncWorktrees` variant**

In `crates/grove-daemon/src/state.rs`, after `StateMessage` enum and before `QueryRequest`:

Add `SyncResult` struct:
```rust
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub workspaces: Vec<Workspace>,
    pub added: Vec<WorkspaceId>,
    pub removed: Vec<WorkspaceId>,
    pub unchanged: Vec<WorkspaceId>,
}
```

Add variant to `StateMessage` enum (before `Shutdown`):
```rust
SyncWorktrees {
    desired: Vec<Workspace>,
    reply: oneshot::Sender<Result<SyncResult, String>>,
},
```

**Step 4: Handle `SyncWorktrees` in the run loop**

In the `run` method's match block (after `RemoveWorkspace` arm), add:
```rust
StateMessage::SyncWorktrees { desired, reply } => {
    let result = self.handle_sync_worktrees(desired);
    if reply.send(result).is_err() {
        debug!("sync reply channel dropped");
    }
    false
}
```

In the `drain_queued_messages` method, add a `SyncWorktrees` arm:
```rust
StateMessage::SyncWorktrees { reply, .. } => {
    if reply.send(Err("daemon is shutting down".to_string())).is_err() {
        debug!("sync reply channel dropped during shutdown drain");
    }
}
```

**Step 5: Implement `handle_sync_worktrees`**

Add method to `DaemonState`:
```rust
fn handle_sync_worktrees(&mut self, desired: Vec<Workspace>) -> Result<SyncResult, String> {
    let desired_ids: HashMap<WorkspaceId, Workspace> =
        desired.into_iter().map(|ws| (ws.id, ws)).collect();

    let current_ids: Vec<WorkspaceId> = self.workspaces.keys().cloned().collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut unchanged = Vec::new();

    // Remove stale workspaces
    for id in &current_ids {
        if !desired_ids.contains_key(id) {
            self.handle_remove_workspace(*id)?;
            removed.push(*id);
        }
    }

    // Add or update desired workspaces
    for (id, ws) in &desired_ids {
        if self.workspaces.contains_key(id) {
            unchanged.push(*id);
        } else {
            added.push(*id);
        }
        self.handle_register_workspace(ws.clone())?;
    }

    let workspaces: Vec<Workspace> = self.workspaces.values().cloned().collect();

    Ok(SyncResult {
        workspaces,
        added,
        removed,
        unchanged,
    })
}
```

**Step 6: Run test to verify it passes**

Run: `cargo test -p grove-daemon sync_worktrees_adds_new_and_removes_stale -- --nocapture`
Expected: PASS

**Step 7: Run full daemon test suite**

Run: `cargo test -p grove-daemon`
Expected: all pass

**Step 8: Commit**

```bash
git add crates/grove-daemon/src/state.rs
git commit -m "feat: add SyncWorktrees message for atomic worktree reconciliation"
```

---

## Task 4: Wire `sync_worktrees` into the socket protocol

**Files:**
- Modify: `crates/grove-daemon/src/socket.rs:89-129` (parse_request)
- Modify: `crates/grove-daemon/src/socket.rs:131-` (query_response_to_socket)
- Modify: `crates/grove-cli/src/client.rs` (add convenience method)
- Test: `crates/grove-daemon/src/socket.rs` (inline tests)

**Step 1: Write failing test for socket parse**

Add to `#[cfg(test)] mod tests` in `crates/grove-daemon/src/socket.rs`:

```rust
#[test]
fn parse_sync_worktrees_request() {
    let req = SocketRequest {
        method: "sync_worktrees".to_string(),
        params: serde_json::json!({
            "worktrees": [
                {"name": "main", "path": "/repo", "branch": "refs/heads/main", "head": "abc123"}
            ]
        }),
    };
    let result = parse_request(&req);
    assert!(result.is_ok());
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p grove-daemon parse_sync_worktrees_request -- --nocapture`
Expected: FAIL

**Step 3: Extend `parse_request` to handle `sync_worktrees`**

The `sync_worktrees` method is different from queries — it's a mutation. It needs to go through `StateMessage::SyncWorktrees`, not `QueryRequest`. The current socket handler routes everything through `QueryRequest`, so we need a small refactor.

Change the socket handler approach: instead of `parse_request` returning only `QueryRequest`, create a `ParsedRequest` enum:

```rust
enum ParsedRequest {
    Query(QueryRequest),
    SyncWorktrees { desired: Vec<grove_lib::Workspace> },
}
```

Update `parse_request` signature to return `Result<ParsedRequest, String>`. Add the `sync_worktrees` match arm:

```rust
"sync_worktrees" => {
    let worktrees = request
        .params
        .get("worktrees")
        .ok_or_else(|| "missing required param: worktrees".to_string())?;

    #[derive(Deserialize)]
    struct WorktreeParam {
        name: String,
        path: String,
        branch: String,
        head: String,
    }

    let params: Vec<WorktreeParam> = serde_json::from_value(worktrees.clone())
        .map_err(|e| format!("invalid worktrees param: {e}"))?;

    let desired: Vec<grove_lib::Workspace> = params
        .into_iter()
        .map(|p| {
            let path = std::path::PathBuf::from(&p.path);
            let id = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, path.to_string_lossy().as_bytes());
            grove_lib::Workspace {
                id,
                name: p.name,
                branch: p.branch,
                path,
                base_ref: String::new(),
                created_at: chrono::Utc::now(),
                last_activity: chrono::Utc::now(),
                metadata: grove_lib::WorkspaceMetadata::default(),
            }
        })
        .collect();

    Ok(ParsedRequest::SyncWorktrees { desired })
}
```

Update `handle_request` to dispatch `ParsedRequest::SyncWorktrees` via `StateMessage::SyncWorktrees` and convert the `SyncResult` to a `SocketResponse`.

**Step 4: Add `sync_worktrees` convenience method to `DaemonClient`**

In `crates/grove-cli/src/client.rs`:

```rust
pub async fn sync_worktrees(&self, worktrees: serde_json::Value) -> Result<DaemonResponse, ClientError> {
    self.request("sync_worktrees", serde_json::json!({ "worktrees": worktrees })).await
}
```

**Step 5: Run tests**

Run: `cargo test -p grove-daemon parse_sync_worktrees_request -- --nocapture`
Expected: PASS

Run: `cargo test -p grove-daemon`
Expected: all pass

**Step 6: Commit**

```bash
git add crates/grove-daemon/src/socket.rs crates/grove-cli/src/client.rs
git commit -m "feat: wire sync_worktrees into socket protocol and CLI client"
```

---

## Task 5: Add the `bootstrap` module to `grove-cli`

**Files:**
- Create: `crates/grove-cli/src/bootstrap.rs`
- Modify: `crates/grove-cli/src/lib.rs:1` (add `pub mod bootstrap`)
- Test: `crates/grove-cli/src/bootstrap.rs` (inline tests)

**Step 1: Write failing tests for `resolve_git_context`**

Create `crates/grove-cli/src/bootstrap.rs` with tests:

```rust
use std::path::PathBuf;

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
    todo!()
}

/// Derive the canonical `.grove/` directory from git context.
pub fn grove_dir_from_context(ctx: &GitContext) -> PathBuf {
    todo!()
}

/// Ensure `.grove/` directory exists and is excluded from git tracking.
pub fn ensure_grove_dir(ctx: &GitContext) -> Result<PathBuf, String> {
    todo!()
}

/// Discover all worktrees via `git worktree list --porcelain`.
pub fn discover_worktrees() -> Result<Vec<DiscoveredWorktree>, String> {
    todo!()
}

/// Parse `git worktree list --porcelain` output.
pub fn parse_worktree_list(output: &str) -> Vec<DiscoveredWorktree> {
    todo!()
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
        assert_eq!(grove_dir_from_context(&ctx), PathBuf::from("/home/user/myproject/.grove"));
    }

    #[test]
    fn grove_dir_works_for_bare_style_common_dir() {
        let ctx = GitContext {
            toplevel: PathBuf::from("/home/user/myproject"),
            common_dir: PathBuf::from("/home/user/myproject.git"),
        };
        // Parent of /home/user/myproject.git is /home/user
        assert_eq!(grove_dir_from_context(&ctx), PathBuf::from("/home/user/.grove"));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p grove-cli parse_worktree_list -- --nocapture`
Expected: FAIL (todo! panics)

**Step 3: Implement `parse_worktree_list`**

```rust
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
                worktrees.push(DiscoveredWorktree { path: p, head: h, branch: branch.take(), name });
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
        worktrees.push(DiscoveredWorktree { path: p, head: h, branch, name });
    }

    worktrees
}

fn derive_name(path: &PathBuf, branch: Option<&str>) -> String {
    match branch {
        Some(b) => b.strip_prefix("refs/heads/").unwrap_or(b).to_string(),
        None => path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}
```

**Step 4: Implement `grove_dir_from_context`**

```rust
pub fn grove_dir_from_context(ctx: &GitContext) -> PathBuf {
    ctx.common_dir
        .parent()
        .unwrap_or(&ctx.toplevel)
        .join(".grove")
}
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p grove-cli parse_worktree_list grove_dir -- --nocapture`
Expected: PASS

**Step 6: Implement `resolve_git_context`**

```rust
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

    Ok(GitContext { toplevel, common_dir })
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
```

**Step 7: Implement `ensure_grove_dir`**

```rust
pub fn ensure_grove_dir(ctx: &GitContext) -> Result<PathBuf, String> {
    let grove_dir = grove_dir_from_context(ctx);

    std::fs::create_dir_all(&grove_dir)
        .map_err(|e| format!("failed to create {}: {e}", grove_dir.display()))?;

    // Add .grove/ to git exclude (not .gitignore — avoids diffs)
    if let Err(e) = add_to_git_exclude(&grove_dir) {
        // Non-fatal: log warning, continue
        eprintln!("warning: could not update git exclude: {e}");
    }

    Ok(grove_dir)
}

fn add_to_git_exclude(grove_dir: &std::path::Path) -> Result<(), String> {
    let exclude_path_output = run_git(&["rev-parse", "--git-path", "info/exclude"])?;
    let exclude_path = PathBuf::from(exclude_path_output.trim());

    // Ensure parent directory exists
    if let Some(parent) = exclude_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create exclude dir: {e}"))?;
    }

    let entry = ".grove/";

    // Check if already present
    if let Ok(contents) = std::fs::read_to_string(&exclude_path) {
        if contents.lines().any(|line| line.trim() == entry) {
            return Ok(());
        }
    }

    // Append
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&exclude_path)
        .map_err(|e| format!("failed to open exclude file: {e}"))?;

    writeln!(file, "{entry}")
        .map_err(|e| format!("failed to write to exclude file: {e}"))?;

    Ok(())
}
```

**Step 8: Implement `discover_worktrees`**

```rust
pub fn discover_worktrees() -> Result<Vec<DiscoveredWorktree>, String> {
    let output = run_git(&["worktree", "list", "--porcelain"])?;
    Ok(parse_worktree_list(&output))
}
```

**Step 9: Add `pub mod bootstrap` to `crates/grove-cli/src/lib.rs`**

Add `pub mod bootstrap;` at line 1.

**Step 10: Run full test suite**

Run: `cargo test -p grove-cli`
Expected: all pass

**Step 11: Commit**

```bash
git add crates/grove-cli/src/bootstrap.rs crates/grove-cli/src/lib.rs
git commit -m "feat: add bootstrap module for git context resolution and worktree discovery"
```

---

## Task 6: Add daemon liveness check and auto-spawn to bootstrap

**Files:**
- Modify: `crates/grove-cli/src/bootstrap.rs`

**Step 1: Add `ensure_daemon` function**

```rust
use crate::client::DaemonClient;

/// Check if the daemon is running; start it if not.
/// Returns a connected `DaemonClient`.
pub async fn ensure_daemon(grove_dir: &std::path::Path) -> Result<DaemonClient, String> {
    let socket_path = grove_dir.join("daemon.sock");
    let client = DaemonClient::new(&socket_path);

    // Try socket ping first (source of truth for liveness)
    if client.status().await.is_ok() {
        return Ok(client);
    }

    // Daemon not responding — spawn it
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

fn spawn_daemon(grove_dir: &std::path::Path) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("cannot find grove executable: {e}"))?;

    std::process::Command::new(exe)
        .args(["daemon", "start"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to spawn daemon: {e}"))?;

    Ok(())
}
```

**Step 2: Run build to verify it compiles**

Run: `cargo build`
Expected: compiles cleanly

**Step 3: Commit**

```bash
git add crates/grove-cli/src/bootstrap.rs
git commit -m "feat: add daemon liveness check and auto-spawn to bootstrap"
```

---

## Task 7: Add the top-level `bootstrap` orchestrator function

**Files:**
- Modify: `crates/grove-cli/src/bootstrap.rs`

**Step 1: Add the orchestrator**

```rust
/// Full bootstrap: resolve git context, ensure .grove/, ensure daemon, discover & sync worktrees.
/// Returns the connected client and sync result.
pub async fn bootstrap() -> Result<(DaemonClient, serde_json::Value), String> {
    let ctx = resolve_git_context()?;

    // Reject bare repos
    let is_bare = run_git(&["rev-parse", "--is-bare-repository"])?;
    if is_bare.trim() == "true" {
        return Err("Grove requires a non-bare repository with worktrees.".to_string());
    }

    let grove_dir = ensure_grove_dir(&ctx)?;
    let client = ensure_daemon(&grove_dir).await?;
    let worktrees = discover_worktrees()?;

    // Build sync payload
    let worktrees_json: Vec<serde_json::Value> = worktrees
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

    let response = client
        .sync_worktrees(serde_json::Value::Array(worktrees_json))
        .await
        .map_err(|e| format!("sync failed: {e}"))?;

    if !response.ok {
        return Err(format!(
            "sync failed: {}",
            response.error.unwrap_or_else(|| "unknown error".to_string())
        ));
    }

    Ok((client, response.data.unwrap_or_default()))
}
```

**Step 2: Run build**

Run: `cargo build`
Expected: compiles cleanly

**Step 3: Commit**

```bash
git add crates/grove-cli/src/bootstrap.rs
git commit -m "feat: add top-level bootstrap orchestrator"
```

---

## Task 8: Update the `grove` binary to call bootstrap

**Files:**
- Modify: `crates/grove/src/main.rs`
- Modify: `crates/grove-cli/src/lib.rs:67-116` (run function)

**Step 1: Update `run` in `grove-cli/src/lib.rs`**

Replace the `Some(Commands::Status) | None` match arm and the surrounding logic. The key change: when the command is `None` (bare `grove`) or `Status`, call `bootstrap::bootstrap()` first, then use the returned client for the status query.

```rust
Some(Commands::Status) | None => {
    // Bootstrap: auto-discover, auto-daemon, auto-sync
    let (client, _sync_data) = crate::bootstrap::bootstrap()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    commands::status::execute(&client, args.json).await?;
}
```

For other commands that need the daemon (`List`, `Conflicts`), also call bootstrap so the daemon is running. Remove the `find_grove_dir` + manual `DaemonClient` construction and replace with:

```rust
let grove_dir = find_grove_dir(std::env::current_dir()?)?;
let socket_path = grove_dir.join("daemon.sock");
let client = DaemonClient::new(&socket_path);
```

becomes (for List and Conflicts):

```rust
let (client, _) = crate::bootstrap::bootstrap()
    .await
    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
```

Keep `daemon stop`/`daemon status` using the old `find_grove_dir` approach — they shouldn't bootstrap.

**Step 2: Update `main.rs` in `grove` binary**

The `find_grove_dir` in `main.rs` (used only for `daemon start`) can stay as-is. The bootstrap in `grove-cli` handles `.grove/` creation for all other commands.

**Step 3: Run build**

Run: `cargo build`
Expected: compiles cleanly

**Step 4: Run full test suite**

Run: `cargo test`
Expected: all pass

**Step 5: Commit**

```bash
git add crates/grove-cli/src/lib.rs crates/grove/src/main.rs
git commit -m "feat: wire bootstrap into CLI entry point"
```

---

## Task 9: Update status rendering for smart output

**Files:**
- Modify: `crates/grove-cli/src/commands/status.rs`
- Test: `crates/grove-cli/src/commands/status.rs` (inline tests)

**Step 1: Write failing test for smart output**

Add tests in `crates/grove-cli/src/commands/status.rs`:

```rust
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
        "overlaps": [{"type": "Symbol", "path": "src/auth.ts", "name": "updateUser"}],
    }]);
    let output = format_smart_status(&data, &workspaces, &analyses);
    assert!(output.contains("Conflicts"));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p grove-cli format_smart_status -- --nocapture`
Expected: FAIL

**Step 3: Implement `format_smart_status`**

Add the function and update `execute` to call it when additional data is available. The `execute` function should fetch `list_workspaces` and `get_all_analyses` in addition to `status`, then call `format_smart_status`.

This is the rendering logic — format based on whether any analysis has a non-Green score.

**Step 4: Run tests**

Run: `cargo test -p grove-cli`
Expected: all pass

**Step 5: Commit**

```bash
git add crates/grove-cli/src/commands/status.rs
git commit -m "feat: smart status output with conflict matrix and merge order"
```

---

## Task 10: Integration test — full bootstrap smoke test

**Files:**
- Modify: `crates/grove/tests/smoke_test.rs`

**Step 1: Add smoke test for `sync_worktrees` over the socket**

```rust
#[tokio::test]
async fn sync_worktrees_registers_and_removes_via_socket() {
    let daemon = TestDaemon::start().await;

    // Sync with 2 worktrees
    let response = daemon.client.sync_worktrees(serde_json::json!([
        {"name": "main", "path": "/repo", "branch": "refs/heads/main", "head": "abc"},
        {"name": "feature", "path": "/repo-feat", "branch": "refs/heads/feature", "head": "def"},
    ])).await.unwrap();
    assert!(response.ok);

    let data = response.data.unwrap();
    assert_eq!(data["added"].as_array().unwrap().len(), 2);

    // Verify via list
    let list = daemon.client.list_workspaces().await.unwrap();
    assert!(list.ok);
    let workspaces = list.data.unwrap();
    assert_eq!(workspaces.as_array().unwrap().len(), 2);

    // Sync again with only main — feature should be removed
    let response = daemon.client.sync_worktrees(serde_json::json!([
        {"name": "main", "path": "/repo", "branch": "refs/heads/main", "head": "abc"},
    ])).await.unwrap();
    assert!(response.ok);
    let data = response.data.unwrap();
    assert_eq!(data["removed"].as_array().unwrap().len(), 1);
    assert_eq!(data["unchanged"].as_array().unwrap().len(), 1);

    daemon.shutdown().await;
}
```

**Step 2: Run test**

Run: `cargo test -p grove sync_worktrees_registers_and_removes_via_socket -- --nocapture`
Expected: PASS

**Step 3: Run full test suite**

Run: `cargo test`
Expected: all 343+ tests pass, plus new ones

**Step 4: Run clippy**

Run: `cargo clippy --workspace`
Expected: no warnings

**Step 5: Commit**

```bash
git add crates/grove/tests/smoke_test.rs
git commit -m "test: add smoke test for sync_worktrees over socket"
```

---

## Task 11: Clean up `.grove/` from the repo

**Files:**
- Remove: `.grove/` directory (created during manual testing earlier)

**Step 1: Remove the test `.grove/` directory**

```bash
rm -rf .grove/
```

**Step 2: Verify `.grove/` is in `.gitignore` or excluded**

Ensure it doesn't show up in `git status`.

**Step 3: Commit if needed**

If `.grove/` was tracked, remove it. Otherwise no commit needed.

---

## Summary

| Task | What it does |
|------|-------------|
| 1 | UUID v5 dependency |
| 2 | Idempotent register/remove |
| 3 | `SyncWorktrees` state message |
| 4 | Socket protocol + client method |
| 5 | Bootstrap module (git context, worktree parsing) |
| 6 | Daemon liveness + auto-spawn |
| 7 | Top-level bootstrap orchestrator |
| 8 | Wire bootstrap into CLI entry point |
| 9 | Smart status rendering |
| 10 | Integration smoke test |
| 11 | Clean up test artifacts |
