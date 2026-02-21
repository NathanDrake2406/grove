# Grove

Cross-worktree conflict intelligence for git. Detects file, hunk, symbol, dependency, and schema overlaps between parallel workstreams before merge time.

Grove watches your git worktrees, continuously analyzes pairwise overlaps, and tells you which branches will conflict before you attempt to merge. Perfect for your multi-agents working in parallel worktrees ;)

## Why

When multiple people (or agents) work in parallel branches, merge conflicts are discovered too late — at merge time. Grove shifts conflict detection left by analyzing worktree diffs against a shared base and scoring how likely they are to collide.

Five overlap layers, from coarse to precise:

| Layer | What it catches | Score |
|-------|----------------|-------|
| **File** | Both branches modified the same file | Yellow |
| **Hunk** | Edits land in overlapping line ranges | Red (adjacent = Yellow) |
| **Symbol** | Same function/type/export modified in both | Red |
| **Dependency** | One branch changes an export that the other imports | Black |
| **Schema** | Both touch migrations, package deps, env config, or routes | Yellow |

The worst overlap determines the pair's **orthogonality score**: Green (safe) < Yellow (review) < Red (likely conflict) < Black (breaking change).

## Install

```sh
brew install NathanDrake2406/tap/grove
```

Or from source:

```sh
cargo install --path crates/grove
```

## Quick start

```sh
grove status                                    # that's it — daemon auto-starts
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
| `grove init <shell>` | Emit shell integration (`zsh`, `bash`, `fish`) |

All read commands accept `--json` for machine-readable output.

## Architecture

Single binary, 4-crate Rust workspace:

```
grove (binary)
  grove-cli ── CLI commands, socket client, terminal rendering
  grove-daemon ── Background daemon, SQLite persistence, file watcher, worker pool
grove-lib ── Pure analysis library (no I/O)
```

The daemon runs an actor model — a single `DaemonState` thread processes all mutations sequentially via `tokio::mpsc` channels. Workers, watchers, and socket connections communicate through channels. No shared mutable state.

`grove-lib` is a deterministic core: given the same inputs, it produces the same outputs. It depends on a `FileSystem` trait, never touches disk directly.

### Language support

Symbol extraction, import/export resolution, and schema detection for:

- TypeScript / JavaScript
- Rust
- Go
- Python
- Java
- C#

### Socket protocol

The daemon exposes an NDJSON protocol over a Unix socket at `.grove/daemon.sock`. Each request is one JSON line, each response is one JSON line.

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

Block until all in-flight analyses finish (or timeout), instead of polling:

```
>> {"method": "await_analysis", "params": {"timeout_ms": 5000}}
<< {"ok": true, "data": {"in_flight": 0, "analysis_count": 3}}
```

`in_flight == 0` means all analyses are complete.

## Development

```sh
cargo build                     # Build all crates
cargo test                      # Run all tests
cargo clippy --workspace        # Lint
cargo fmt --check               # Format check
cargo test -p grove-lib         # Test core library only
cargo test -p grove-daemon      # Test daemon
```

## License

MIT OR Apache-2.0
