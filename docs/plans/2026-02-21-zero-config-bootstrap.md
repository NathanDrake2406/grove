# Zero-Config Bootstrap

**Date:** 2026-02-21
**Status:** Proposed
**Scope:** grove-cli, grove-daemon (socket protocol), grove (binary entry point)
**Unchanged:** grove-lib

## Problem

Grove requires manual setup before it does anything useful: create `.grove/`, start the daemon, register worktrees. The ideal UX is typing `grove` and getting conflict intelligence immediately.

## Design

### UX

Run `grove` anywhere inside a git repo that has worktrees. Everything bootstraps automatically.

Clean output:

```
Grove · 3 worktrees · base: main (a1b2c3d)
────────────────────────────────────────────────
  auth-refactor      ✓ clean
  payment-fix        ✓ clean
  new-onboarding     ✓ clean

All pairs independent — merge in any order.
```

Conflict output:

```
Grove · 3 worktrees · base: main (a1b2c3d)
────────────────────────────────────────────────
  auth-refactor      ● 1 conflict
  payment-fix        ● 1 conflict
  new-onboarding     ✓ clean

Conflicts
────────────────────────────────────────────────
  auth-refactor ↔ payment-fix         RED
    ├ symbol: updateUser() modified in both
    └ hunk: src/middleware/auth.ts lines 42-58

Merge order: auth-refactor → payment-fix → new-onboarding
```

Single worktree (no pairs to analyze):

```
Grove · 1 worktree · base: main (a1b2c3d)
────────────────────────────────────────────────
  main      (only worktree)

Add worktrees with `git worktree add` — Grove will detect them automatically.
```

### Bootstrap Sequence

Triggered by `grove` (no args) or `grove status`. Steps run in order; each is idempotent.

#### 1. Resolve git context

Use `git rev-parse` to find the repo topology:

```
git rev-parse --show-toplevel       # → /home/user/myproject
git rev-parse --git-common-dir      # → /home/user/myproject/.git
git rev-parse --is-bare-repository  # → false
```

`--git-common-dir` returns the shared `.git/` directory that all worktrees share. This is the canonical anchor point. It works correctly for both the main checkout and linked worktrees (where `.git` is a file pointing to `../.git/worktrees/<name>`).

Bare repos: exit with a clear error — "Grove requires a non-bare repository with worktrees."

#### 2. Ensure `.grove/` in the common git dir

Place `.grove/` as a sibling to the common git dir:

```
common_git_dir = git rev-parse --git-common-dir  # e.g. /home/user/myproject/.git
grove_dir = common_git_dir/../.grove              # e.g. /home/user/myproject/.grove
```

This guarantees all worktrees share one daemon, one DB, one socket. `mkdir -p` is idempotent.

Add `.grove/` to git's exclude file (not `.gitignore`, which would show up in diffs):

```
exclude_path = git rev-parse --git-path info/exclude
```

Append `.grove/` if not already present. If the write fails (permissions, read-only fs), log a warning and continue — bootstrap should not fail over this.

#### 3. Ensure daemon is running

Check liveness by **socket ping first**, not PID file:

1. Try connecting to `.grove/daemon.sock` and sending `{"method":"status","params":{}}`.
2. If the socket responds: daemon is alive, proceed.
3. If the socket is missing or connection refused: check PID file. If PID file exists and process is alive (`kill(pid, 0)`), wait briefly and retry socket (daemon may be starting up).
4. If no daemon is running: spawn it.

Spawning: the `grove` binary forks and execs `grove daemon start` as a background process. The parent process polls the socket (with backoff, max ~3 seconds) until it gets a response. If the daemon fails to start within the timeout, exit with an error.

This avoids PID-reuse false positives — the socket ping is the source of truth.

#### 4. Discover worktrees

Parse `git worktree list --porcelain` output:

```
worktree /home/user/myproject
HEAD abc123def456
branch refs/heads/main

worktree /home/user/myproject-auth
HEAD def789abc012
branch refs/heads/auth-refactor

worktree /home/user/myproject-payments
HEAD 456789def012
branch refs/heads/payment-fix
```

Extract for each worktree: path, HEAD commit, branch name. Derive a human-readable name from the branch (strip `refs/heads/`), falling back to the directory basename if detached HEAD.

#### 5. Sync worktrees (single atomic command)

Send one `sync_worktrees` request to the daemon with the full desired state:

```json
{
  "method": "sync_worktrees",
  "params": {
    "worktrees": [
      {"name": "main", "path": "/home/user/myproject", "branch": "refs/heads/main", "head": "abc123"},
      {"name": "auth-refactor", "path": "/home/user/myproject-auth", "branch": "refs/heads/auth-refactor", "head": "def789"},
      {"name": "payment-fix", "path": "/home/user/myproject-payments", "branch": "refs/heads/payment-fix", "head": "456789"}
    ]
  }
}
```

The daemon's state actor reconciles atomically:

- **New worktrees** (path not previously registered): assign a deterministic `WorkspaceId` (UUID v5 from the worktree path), create `Workspace`, persist to DB.
- **Existing worktrees** (path matches): update metadata if branch/HEAD changed. No-op if unchanged.
- **Stale worktrees** (previously registered, not in the new list): remove from state, clean up overlays and pair analyses, delete from DB.
- **Watcher updates**: register new paths with the file watcher, unregister removed paths.

Response: the full updated workspace list (so the CLI can render immediately without a second round-trip).

```json
{
  "ok": true,
  "data": {
    "workspaces": [...],
    "added": ["payment-fix"],
    "removed": [],
    "unchanged": ["main", "auth-refactor"]
  }
}
```

Deterministic workspace IDs (UUID v5 seeded from the absolute worktree path) ensure that IDs are stable across daemon restarts and bootstrap re-runs. This also fixes the name-vs-UUID mismatch — the CLI can resolve names to IDs locally since it knows the path→ID mapping.

#### 6. Query and render

Fetch all pair analyses via `get_all_analyses`. Render the smart output:

- If all pairs are Green (or no pairs exist): clean dashboard.
- If any pair is Yellow/Red/Black: conflict matrix with overlap details and merge order.

For initial bootstrap (daemon just started, no analysis complete yet): show "Analyzing..." placeholder. The daemon will compute pair analyses in the background; subsequent `grove` invocations will show results.

### Idempotency Fixes

`RegisterWorkspace` (state.rs): check if workspace already exists by path before enforcing max count. If it exists, update metadata and return Ok. Only count toward the limit if truly new.

`RemoveWorkspace` (state.rs): if the workspace doesn't exist, return Ok (no-op) instead of an error.

### Changes Summary

| Crate | What changes |
|-------|-------------|
| `grove` (binary) | Bootstrap sequence before CLI dispatch. Daemon spawning logic. |
| `grove-cli` | New `bootstrap` module. Updated `status` rendering. Name→ID resolution. |
| `grove-daemon` (socket) | New `sync_worktrees` method in `parse_request`. |
| `grove-daemon` (state) | New `SyncWorktrees` message variant. Idempotent register/remove. Deterministic IDs. |
| `grove-lib` | No changes. |

### Edge Cases

- **No worktrees besides main checkout**: register the single worktree. Show "Add worktrees with `git worktree add`" hint. No pair analysis needed.
- **Worktree added/removed between runs**: next `grove` invocation syncs automatically.
- **Concurrent `grove` invocations**: `sync_worktrees` is atomic in the state actor. Multiple clients sending the same desired state converge to the same result.
- **Daemon crashes**: next `grove` invocation detects dead socket, restarts daemon, re-syncs.
- **`.grove/` manually deleted**: next `grove` invocation recreates it and restarts everything.
- **Permission errors on `.grove/` creation**: fail with a clear error message.

### Future (Phase 2)

- Live TUI with ratatui (lazygit-style interactive view)
- `grove watch` mode that streams updates
- Config file support (`.grove/config.toml`) for base branch, ignore patterns, etc.
