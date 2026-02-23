# Grove

Cross-worktree conflict intelligence for git. Detects file, hunk, symbol, dependency, and schema overlaps between parallel workstreams before merge time.

Grove watches your git worktrees, continuously analyzes pairwise overlaps, and tells you which branches will conflict before you attempt to merge. Perfect for your multi-agents working in parallel worktrees ;)

![Grove TUI dashboard](assets/demo.png)

## Why

When multiple people (or agents) work in parallel branches, merge conflicts are discovered too late, at merge time. Grove shifts conflict detection left by analyzing worktree diffs against a shared base and scoring how likely they are to collide. You can setup your agents to check this automatically.

Five overlap layers, from coarse to precise:

| Layer | What it catches | Score |
|-------|----------------|-------|
| **File** | Both branches modified the same file | Yellow |
| **Hunk** | Edits land in overlapping line ranges | Red (adjacent = Yellow) |
| **Symbol** | Same function/type/export modified in both | Red |
| **Dependency** | One branch changes an export that the other imports | Black |
| **Schema** | Both touch migrations, package deps, env config, or routes | Yellow |

The worst overlap determines the pair's **orthogonality score**: Green (safe) < Yellow (review) < Red (likely conflict) < Black (breaking change).

**Supported languages:** TypeScript/JavaScript, Rust, Go, Python, Java, C#

## Install

```sh
brew install NathanDrake2406/tap/grove
```

Or via npm:

```sh
npm install -g @nathan2406/grove
# or run directly
npx @nathan2406/grove check
```

Or from source:

```sh
cargo install --path crates/grove
```

## Quick start

```sh
grove status                                    # that's it, daemon auto-starts
grove conflicts feat/auth feat/payments         # compare two branches
grove conflicts feat/auth feat/payments --json  # machine-readable
```

## Shell integration

Grove provides a `gr` shell wrapper that adds `gr switch` for quick worktree navigation:

```sh
# Add to your shell profile
eval "$(grove init zsh)"    # or bash, fish

# Switch to a worktree (cd's into it)
gr switch feat/auth

# Everything else passes through to grove
gr status
gr conflicts feat/auth feat/payments
```

## Commands

| Command | Description |
|---------|-------------|
| `grove` | Open the live TUI dashboard (interactive terminal) |
| `grove status` | Workspace list + conflict summary |
| `grove list` | Table of all tracked worktrees |
| `grove conflicts <a> <b>` | Pairwise conflict detail between two branches |
| `grove dashboard` | Explicit TUI dashboard |
| `grove daemon start` | Start the background daemon |
| `grove daemon stop` | Stop the daemon |
| `grove daemon status` | Daemon health check |
| `grove check` | Exit 0 if clean, exit 1 with conflict one-liners on stderr |
| `grove init <shell>` | Emit shell integration (`zsh`, `bash`, `fish`) |

All read commands accept `--json` for machine-readable output.

## Claude Code hook

Grove integrates with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) via a post-tool hook that runs `grove check` after every file edit. When a conflict is detected, Claude sees the warning in its tool output and can course-correct before the problem compounds.

Add this to your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "grove check 2>&1 || true"
          }
        ]
      }
    ]
  }
}
```

After any file edit, Claude will see output like:

```
[conflict] feat/payments: both branches modify processPayment() in src/shared.ts (+2 more)
[minor] feat/auth: 3 file(s) modified by both branches

Run `grove conflicts <this-branch> <other-branch>` for full details.
```

Or silence when clean (exit 0, no output).

Labels are designed to be self-explanatory for AI agents:

| Label | Meaning | Action |
|-------|---------|--------|
| `[minor]` | Same files touched, nearby code | Be aware, usually safe |
| `[conflict]` | Same symbols modified or overlapping lines | Coordinate before merging |
| `[breaking]` | Export change breaks downstream imports | Must resolve before merging |

### How it works

1. Claude edits a file via `Edit`, `Write`, or `MultiEdit`
2. The hook runs `grove check` in the current worktree
3. If conflicts exist, `grove check` prints one-liners to stderr and exits 1
4. The `|| true` ensures the hook never blocks Claude (conflicts are advisory)
5. Claude sees the conflict warnings and can adjust its approach

### JSON mode for structured parsing

For agents that prefer structured output, use `grove check --json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "grove check --json 2>&1 || true"
          }
        ]
      }
    ]
  }
}
```

This returns a JSON object with `workspace`, `clean`, and `conflicts` fields.

## Architecture

Single binary, 5-crate Rust workspace:

```
grove (binary entry point)
├── grove-cli    ── CLI commands, socket client, terminal rendering
├── grove-daemon ── Background daemon, SQLite persistence, file watcher, worker pool
├── grove-tui    ── Interactive terminal dashboard (ratatui + crossterm)
└── grove-lib    ── Pure analysis library (no I/O, no side effects)
```

### Actor model

The daemon uses an actor concurrency model. A single `DaemonState` thread owns all mutable state and processes messages sequentially via `tokio::mpsc` channels. Workers, file watchers, and socket connections communicate exclusively through channels. No `RwLock`, no `DashMap`, no shared mutable state.

```
                ┌──────────────┐
  Socket ──────>│              │
  connections   │  DaemonState │──────> Workers (analysis)
                │   (actor)    │
  File ────────>│              │──────> SQLite (persistence)
  watcher       └──────────────┘
                    ▲      │
                    │      ▼
                 oneshot  mpsc
                 (reply)  (commands/queries)
```

Commands (`FileChanged`, `BaseRefChanged`, `SyncWorktrees`) mutate state. Queries (`Status`, `ListWorkspaces`, `Conflicts`) return data without mutation. The two are never mixed.

### Functional core, imperative shell

`grove-lib` is a pure analysis library with no I/O. Given the same inputs, it produces the same outputs. It depends on a `FileSystem` trait, never touches disk directly. This makes it fast to test: all unit tests use `InMemoryFileSystem` with zero disk access.

The daemon is the imperative shell. It reads the filesystem, calls the core, and persists results. Time, filesystem contents, and configuration are inputs to the core, not ambient state it reaches for.

### Daemon lifecycle

The daemon daemonizes via double-fork synchronously, single-threaded, **before** the tokio runtime is constructed. Forking after tokio spawns threads causes mutex deadlocks. State is persisted to SQLite (WAL mode) and survives restarts. Analysis results are recovered on daemon restart without re-computation.

### Socket protocol

The daemon exposes an NDJSON protocol over a Unix socket at `.grove/daemon.sock`. Each request is one JSON line, each response is one JSON line. Maximum line size: 1 MiB.

```
Request:  {"method": "status", "params": {}}
Response: {"ok": true, "data": {"workspace_count": 3, "analysis_count": 2, ...}}
```

Available methods: `status`, `list_workspaces`, `get_workspace`, `conflicts`, `get_all_analyses`, `await_analysis`, `sync_worktrees`, `subscribe`, `shutdown`.

#### Event subscription

Agents and tools can subscribe to real-time events instead of polling:

```
>> {"method": "subscribe", "params": {}}
<< {"ok": true, "data": {"subscribed": true}}
<< {"event": "analysis_started", "data": {"workspace_a": "...", "workspace_b": "..."}}
<< {"event": "analysis_complete", "data": {"workspace_a": "...", "workspace_b": "...", "score": "Yellow"}}
```

Events: `analysis_started`, `analysis_complete`, `workspace_added`, `workspace_removed`, `base_ref_changed`.

#### Await analysis

Block until all in-flight analyses finish (or timeout) instead of polling:

```
>> {"method": "await_analysis", "params": {"timeout_ms": 5000}}
<< {"ok": true, "data": {"in_flight": 0, "analysis_count": 3}}
```

`in_flight == 0` means all analyses are complete.

## Performance

93% test coverage across the workspace. The daemon is stress-tested against adversarial conditions:

- **Load**: 500 concurrent connections, 250 requests across 50 parallel clients, 100-connection burst tests. 200 queries fired while 190 pairwise analyses run concurrently. 50 rapid sync churn iterations with no sleep between. Memory growth capped at <500 MB under sustained load.
- **Failure recovery**: Base ref changes mid-analysis, worktree removal while analysis is in-flight, rapid repeated base ref changes (git fetch storms), and daemon restart with SQLite recovery. Post-restart analysis results are recovered without re-computation.
- **Adversarial input**: 22 malformed NDJSON protocol variants (binary garbage, truncated JSON, deeply nested objects, null bytes, 10,000-character method strings). NDJSON boundary testing at 1 MiB. 200-connection rapid connect/disconnect waves. Slowloris attack simulation across 20 simultaneous connections. Circuit breaker trip via 400-file creation storm.
- **Scoring invariants**: Scales from 5 to 15 worktrees with overlapping modifications. All C(N,2) pairs complete within timeout, no Green scores with overlaps (monotonicity), all non-Green pairs have non-empty overlap lists.

### Key defaults

| Parameter | Default |
|-----------|---------|
| Worker pool | CPU count, clamped 1-8 |
| Analysis timeout | 30s per pair |
| AST cache | 5,000 entries (LRU) |
| Max worktrees | 20 |
| Debounce window | 500ms |
| Circuit breaker | 100 files/window triggers full re-index |
| Socket idle timeout | 5 min |
| Max file size | 1 MB (skipped for parsing) |

## Development

```sh
cargo build                     # Build all crates
cargo test                      # Run all tests
cargo clippy --workspace        # Lint
cargo fmt                       # Format
cargo test -p grove-lib         # Test core library only
cargo test -p grove-daemon      # Test daemon
```

## License

MIT OR Apache-2.0
