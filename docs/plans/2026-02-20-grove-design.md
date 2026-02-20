# Grove: Git Worktree Workspace Manager with Cross-Worktree Conflict Intelligence

## Overview

Grove manages git worktrees as a system, not as independent folders. Its core value proposition is the **orthogonality analysis engine**: for any pair of active workspaces, Grove continuously answers whether those two workstreams are independent or on a collision course.

Every other worktree tool treats worktrees as isolated. Grove treats them as interacting nodes in a dependency graph.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Name | Grove | Short (5 chars), evocative (group of trees), easy to type |
| Format | CLI-first | Designed for future dashboard/IDE portability via JSON protocol |
| Architecture | Rust core + single binary | Library-first internals, single `grove` binary for distribution |
| Language analysis | Pluggable `LanguageAnalyzer` trait | Ships with TS/JS + Rust. Community adds others |
| Analysis layers | All 5 (file, hunk, symbol, dependency, schema) | Full blast-radius detection from v1 |
| Trigger | Background daemon with filesystem watching | Always-current analysis via `notify` crate |
| Concurrency | Actor model (tokio mpsc) | Single state-owner thread, no shared locks |
| Target | OSS release from day one | README, CI, release binaries, Homebrew |

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     grove-lib (crate)                        │
│  Depends on FileSystem trait, not filesystem directly.       │
│  Owns: analysis logic, tree-sitter, diffing, scoring.       │
│  Does NOT own: git operations, caching, daemon lifecycle.    │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                    grove (single binary)                      │
│                                                              │
│  CLI mode:  $ grove status / create / retire / conflicts     │
│             Connects to daemon via Unix socket.              │
│             If daemon not running, auto-spawns it.           │
│                                                              │
│  Daemon mode: $ grove daemon start                           │
│               Watches filesystem (notify crate).             │
│               Maintains warm AST cache + incremental parse.  │
│               Sole owner of SQLite state.                    │
│               Serves NDJSON over Unix socket.                │
│                                                              │
│  Shared: Same binary, mode selected by subcommand.           │
│  Daemonization occurs synchronously BEFORE tokio runtime.    │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **grove-lib uses a `FileSystem` trait.** Production uses `MmapFileSystem` for memory-mapped I/O. Tests use `InMemoryFileSystem` for deterministic, fast execution. The library never touches the disk directly.

2. **CLI always talks to daemon via Unix socket.** The daemon is the sole owner of SQLite and in-memory state. If the daemon isn't running, the CLI auto-starts it (fork to background, wait for socket bind, then query). Same pattern as Docker.

3. **Single binary, multiplexed.** `grove-cli` and `grove-daemon` are library crates. The root `grove` crate is the only binary. It inspects `argv[1]` and dispatches to CLI or daemon mode. Simplifies distribution (one binary to install).

4. **Synchronous daemonization before tokio.** The daemon must double-fork and detach before constructing the tokio runtime. Forking after tokio spawns worker threads causes permanent mutex deadlocks in the child process. The `main()` function daemonizes synchronously, then builds the runtime in the detached child.

### FileSystem Trait

```rust
trait FileSystem: Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Bytes>;
    fn exists(&self, path: &Path) -> bool;
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>>;
}

// Production: MmapFileSystem (memory-mapped I/O, zero-copy where possible)
// Testing: InMemoryFileSystem (HashMap<PathBuf, Vec<u8>>)
```

### LanguageAnalyzer Trait

```rust
trait LanguageAnalyzer: Send + Sync {
    fn language_id(&self) -> &str;
    fn file_extensions(&self) -> &[&str];
    fn extract_symbols(&self, tree: &Tree, source: &[u8]) -> Vec<Symbol>;
    fn extract_imports(&self, tree: &Tree, source: &[u8]) -> Vec<Import>;
    fn resolve_call_graph(&self, symbols: &[Symbol], imports: &[Import]) -> CallGraph;
    fn is_schema_file(&self, path: &Path) -> bool;
}
```

Ships with: `TypeScriptAnalyzer`, `RustAnalyzer`. Pluggable for community additions (Go, C#, etc).

---

## 2. Data Model

### Core Types

```rust
// === Workspace Identity ===

struct Workspace {
    id: WorkspaceId,              // UUID, stable across renames
    name: String,                 // User-facing name (e.g., "auth-refactor")
    branch: String,               // Git branch name
    path: PathBuf,                // Worktree filesystem path
    base_ref: String,             // Merge base (e.g., "main")
    created_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    metadata: WorkspaceMetadata,
}

struct WorkspaceMetadata {
    description: Option<String>,
    issue_url: Option<String>,    // Linked Jira/Linear/GitHub issue
    pr_url: Option<String>,
}

// === Change Analysis ===

struct WorkspaceChangeset {
    workspace_id: WorkspaceId,
    merge_base: CommitId,
    changed_files: Vec<FileChange>,
    commits_ahead: u32,
    commits_behind: u32,
}

struct FileChange {
    path: PathBuf,
    change_type: ChangeType,       // Added, Modified, Deleted, Renamed
    hunks: Vec<Hunk>,
    symbols_modified: Vec<Symbol>,
    exports_changed: Vec<ExportDelta>,
}

enum ExportDelta {
    Added(Symbol),
    Removed(Symbol),
    SignatureChanged { old: Signature, new: Signature },
}

// === Orthogonality Analysis ===

struct WorkspacePairAnalysis {
    workspace_a: WorkspaceId,
    workspace_b: WorkspaceId,
    score: OrthogonalityScore,
    overlaps: Vec<Overlap>,        // ALL overlaps across ALL layers
    merge_order_hint: MergeOrder,
    last_computed: DateTime<Utc>,
}

enum OrthogonalityScore {
    Green,   // Fully independent. Will merge cleanly.
    Yellow,  // Overlapping files, different regions. Likely resolvable.
    Red,     // Same logic touched. Expect conflicts.
    Black,   // Structural dependency. Must sequence, not merge independently.
}

enum Overlap {
    File {
        path: PathBuf,
        a_change: ChangeType,
        b_change: ChangeType,
    },
    Hunk {
        path: PathBuf,
        a_range: LineRange,
        b_range: LineRange,
        distance: u32,
    },
    Symbol {
        path: PathBuf,
        symbol: Symbol,
        a_modification: String,
        b_modification: String,
    },
    Dependency {
        changed_in: WorkspaceId,
        changed_file: PathBuf,
        changed_export: ExportDelta,
        affected_file: PathBuf,
        affected_usage: Vec<Location>,
    },
    Schema {
        category: SchemaCategory,  // Migration, PackageDep, EnvConfig, Route, CI
        a_file: PathBuf,
        b_file: PathBuf,
        detail: String,
    },
}
```

### Import Graph (Base + Overlay Model)

The import graph represents the module dependency structure of the codebase. A **base graph** reflects the state of the base branch. Each worktree gets an **overlay** representing its divergence from the base.

```rust
struct ImportGraph {
    // Forward edges: file -> files it imports
    imports: HashMap<FileId, Vec<(FileId, Vec<ImportedSymbol>)>>,
    // Reverse edges: file -> files that import from it
    dependents: HashMap<FileId, Vec<(FileId, Vec<ImportedSymbol>)>>,
    // Symbol table: file -> exported symbols with signatures
    exports: HashMap<FileId, Vec<ExportedSymbol>>,
}

struct GraphOverlay {
    modified_imports: HashMap<PathBuf, Vec<Import>>,
    modified_exports: HashMap<PathBuf, Vec<Export>>,
    added_files: HashMap<PathBuf, (Vec<Import>, Vec<Export>)>,
    removed_files: HashSet<PathBuf>,
}
```

To analyze a worktree pair: load the base graph, apply each worktree's overlay to produce two virtual views, compare the views for dependency overlap.

### Scoring Algorithm

All layers always run. No short-circuiting. The score is the maximum severity across all detected overlaps. The overlaps vector contains every issue from every layer so the developer sees the full blast radius.

```
for each workspace pair (A, B):
    overlaps = []
    overlaps.extend(compute_file_overlaps(A, B))
    overlaps.extend(compute_hunk_overlaps(A, B))
    overlaps.extend(compute_symbol_overlaps(A, B))
    overlaps.extend(compute_schema_overlaps(A, B))
    overlaps.extend(compute_dependency_overlaps(A, B))
    score = max(overlaps.map(|o| o.severity()))
```

The dependency layer is the most expensive but cannot be skipped. A pair with zero file overlap can still be Black if one workspace changes a function signature that the other depends on.

### Merge Order Computation

Given N workspaces targeting the same base branch:
1. Build a directed graph: edge A->B means "A should merge before B"
2. Heuristic: workspace with fewer changes and less dependency overlap merges first
3. Topological sort for optimal sequence
4. Cycles flagged as "needs manual coordination"

### SQLite Schema

```sql
CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    branch TEXT NOT NULL,
    path TEXT NOT NULL,
    base_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    metadata_json TEXT
);

-- Base import graph (state of the base branch)
CREATE TABLE base_import_graph (
    file_path TEXT PRIMARY KEY,
    imports_json TEXT NOT NULL,
    exports_json TEXT NOT NULL,
    ast_hash TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Per-worktree deltas from the base graph
CREATE TABLE workspace_graph_deltas (
    workspace_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    delta_type TEXT NOT NULL,     -- modified, added, removed
    imports_json TEXT,
    exports_json TEXT,
    ast_hash TEXT NOT NULL,
    PRIMARY KEY (workspace_id, file_path)
);

CREATE TABLE pair_analyses (
    workspace_a TEXT NOT NULL,
    workspace_b TEXT NOT NULL,
    score TEXT NOT NULL,
    overlaps_json TEXT NOT NULL,
    merge_order_hint TEXT,
    computed_at TEXT NOT NULL,
    PRIMARY KEY (workspace_a, workspace_b)
);

CREATE TABLE workspace_files (
    workspace_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    change_type TEXT NOT NULL,
    hunks_json TEXT,
    symbols_json TEXT,
    PRIMARY KEY (workspace_id, file_path)
);
```

---

## 3. CLI Interface

### Shell Integration

The `grove` binary cannot change the parent shell's working directory. Grove provides a shell function via `grove init`:

```sh
# User adds to .zshrc / .bashrc / config.fish:
eval "$(grove init zsh)"
```

This creates a `gr` shell function:

```sh
gr() {
    if [[ "$1" == "switch" ]]; then
        local target=$(command grove switch --print-path "${@:2}")
        if [[ -n "$target" ]]; then
            cd "$target"
        fi
    else
        command grove "$@"
    fi
}
```

`gr switch auth-refactor` changes directory natively. No subshells.

### Command Set

```
grove status [--json]               # Dashboard: all workspaces + conflict matrix
grove create <name> [--branch <branch>] [--from <base>] [--issue <url>]
grove switch <name>                 # Opens editor at worktree path
grove switch --print-path <name>    # Prints path (for shell function)
grove list [--stale]                # Compact workspace list
grove conflicts [<a> [<b>]]         # Detailed conflict report
grove conflicts --preview <name>    # Simulated merge conflict preview
grove retire <name> | --auto        # Clean up merged workspaces
grove rebase <name>                 # Rebase single workspace
grove rebase --sequence             # Guided sequential rebase of all workspaces
grove rebase --continue             # Resume after conflict resolution
grove merge-order [--explain]       # Optimal merge sequence
grove daemon start | stop | status  # Daemon lifecycle
grove config [set <key> <value>]    # Configuration
grove init <shell>                  # Shell function setup (zsh/bash/fish)
```

### Output Design

**`grove status` (primary view):**

```
$ grove status

 WORKSPACES                              BASE: main (2 behind remote)
 ─────────────────────────────────────────────────────────────────
 auth-refactor     feature/auth    ↑3  14 files  3 modules   2h ago
 payment-fix       fix/payment     ↑1   3 files  1 module   30m ago
 new-onboarding    feature/onboard ↑0   8 files  2 modules   1d ago
 cache-experiment  experiment/cache ↑2   5 files  1 module    4d ago ⚠ stale

 CONFLICTS
 ─────────────────────────────────────────────────────────────────
 auth-refactor ←→ payment-fix                              ■ RED
   payment/checkout.ts      both modify processPayment()
   payment/types.ts         overlapping hunks (lines 12-30 vs 18-45)

 auth-refactor ←→ new-onboarding                           ■ YELLOW
   shared/auth.ts           both modify, different regions

 payment-fix ←→ new-onboarding                             ■ BLACK
   payment-fix changes processPayment() signature
   new-onboarding calls processPayment() in onboard/payment-step.ts:47

 MERGE ORDER (suggested)
 ─────────────────────────────────────────────────────────────────
 1. new-onboarding  →  2. auth-refactor  →  3. payment-fix
 cache-experiment: independent, merge anytime
```

**`grove conflicts <a> <b>` (detailed pair view):**

```
$ grove conflicts auth-refactor payment-fix

 auth-refactor ←→ payment-fix                               ■ RED
 ────────────────────────────────────────────────────────────────

 FILE OVERLAPS (2 files)
   payment/checkout.ts   Modified in both
   payment/types.ts      Modified in both

 HUNK OVERLAPS
   payment/types.ts
     auth-refactor: lines 12-30 (PaymentConfig interface)
     payment-fix:   lines 18-45 (PaymentConfig + PaymentResult)
     ↳ 12 lines overlap

 SYMBOL OVERLAPS
   payment/checkout.ts
     processPayment()  modified in both workspaces
     auth-refactor: adds auth token parameter
     payment-fix:   changes return type to Result<Payment, Error>

 DEPENDENCY IMPACTS
   (none beyond direct overlaps)

 SCHEMA/CONFIG
   (none detected)

 MERGE PREVIEW
   If auth-refactor merges first, payment-fix will see:
     payment/checkout.ts: 1 conflict region (processPayment signature)
     payment/types.ts:    1 conflict region (PaymentConfig lines 18-30)
```

**`grove rebase --sequence` (guided sequential rebase):**

```
$ grove rebase --sequence

 Rebase sequence (optimal order):
 1. new-onboarding    → clean rebase expected
 2. auth-refactor     → 1 conflict region predicted
 3. payment-fix       → depends on auth-refactor landing first

 Proceed? [y/N] y

 [1/3] Rebasing new-onboarding... ✓ clean
 [2/3] Rebasing auth-refactor...
   ✗ Conflict in payment/checkout.ts
   Dropping you into the worktree to resolve.
   Run `grove rebase --continue` when ready.
```

**JSON output:** All commands support `--json` for machine consumption by IDE plugins, web dashboards, or scripts.

---

## 4. Daemon Architecture

### Process Lifecycle

```
grove daemon start
  │
  ├─ Parse args synchronously (no tokio yet)
  ├─ Double-fork, setsid, detach I/O (synchronous, single-threaded)
  ├─ Write PID to .grove/daemon.pid
  ├─ Build tokio runtime AFTER daemonization
  │
  ├─ INITIALIZATION
  │   ├─ Load config from .grove/config.toml
  │   ├─ Bind Unix socket at .grove/daemon.sock
  │   ├─ Discover all worktrees (git worktree list)
  │   ├─ Load or build base import graph from SQLite
  │   ├─ Compute per-worktree deltas
  │   └─ Run initial orthogonality analysis for all pairs
  │
  ├─ WATCH PHASE (main event loop)
  │   ├─ Filesystem watcher (notify crate)
  │   │   ├─ Watches all worktree paths
  │   │   ├─ Watches .git/refs/remotes/ (base branch changes)
  │   │   ├─ Per-worktree .gitignore filtering (ignore crate)
  │   │   └─ Ignores node_modules, target, dist, .git/objects
  │   │
  │   ├─ On file change in worktree X:
  │   │   ├─ Debounce (500ms window, configurable)
  │   │   ├─ Circuit breaker: >100 files per window → full re-index
  │   │   ├─ Incremental tree-sitter reparse of changed file
  │   │   ├─ Update workspace X's graph overlay
  │   │   ├─ Recompute pair analyses for pairs involving X
  │   │   └─ Persist results to SQLite
  │   │
  │   ├─ On base ref change:
  │   │   ├─ Compare new hash vs stored base_commit
  │   │   ├─ If unchanged: no-op (fetch pulled unrelated branches)
  │   │   ├─ If changed: rebuild base graph, recompute all deltas
  │   │   └─ Recompute all pair analyses
  │   │
  │   └─ On socket request from CLI:
  │       ├─ Parse NDJSON request via LinesCodec
  │       ├─ Send query to state actor, receive response via oneshot
  │       └─ Return NDJSON response
  │
  └─ SHUTDOWN
      ├─ Flush pending writes to SQLite
      ├─ Remove PID file and socket
      └─ Exit cleanly
```

### Entry Point (Fork-Safe)

```rust
fn main() {
    let args = parse_args();

    if args.is_daemon_start() {
        // Daemonize synchronously, single-threaded, BEFORE tokio
        daemonize::Daemonize::new()
            .pid_file(".grove/daemon.pid")
            .start()
            .expect("failed to daemonize");

        // Build tokio runtime ONLY in the detached child
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(grove_daemon::run(args));
    } else {
        // CLI mode
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(grove_cli::run(args));
    }
}
```

### Concurrency Model (Actor)

The daemon uses an actor model. A single state-owner thread holds all mutable state. Workers, watchers, and socket handlers communicate exclusively via channels.

```rust
enum StateMessage {
    FileChanged {
        worktree: WorkspaceId,
        path: PathBuf,
        content: Bytes,
    },
    AnalysisComplete {
        pair: (WorkspaceId, WorkspaceId),
        result: WorkspacePairAnalysis,
    },
    Query {
        request: QueryRequest,
        reply: oneshot::Sender<QueryResponse>,
    },
    BaseRefChanged {
        new_commit: CommitHash,
    },
    WorktreeReindexComplete {
        worktree: WorkspaceId,
        overlay: GraphOverlay,
    },
}
```

No shared locks. No `RwLock<DaemonState>`. No `dashmap`. The state thread processes messages sequentially. Workers send results via `tokio::mpsc`. Socket handlers request data via `tokio::oneshot` request/response pairs.

### In-Memory State

```rust
struct DaemonState {
    config: GroveConfig,
    workspaces: HashMap<WorkspaceId, Workspace>,
    base_graph: ImportGraph,
    base_commit: CommitHash,
    workspace_overlays: HashMap<WorkspaceId, GraphOverlay>,
    ast_cache: LruCache<(WorkspaceId, PathBuf), tree_sitter::Tree>,  // Count-limited
    pair_analyses: HashMap<(WorkspaceId, WorkspaceId), WorkspacePairAnalysis>,
    rebase_state: Option<RebaseSequenceState>,
}
```

### Socket Protocol (NDJSON)

Newline-delimited JSON over Unix socket. Uses `tokio-util`'s `LinesCodec` with `Framed<UnixStream, LinesCodec>` to handle socket fragmentation and partial reads.

**Request format:**
```json
{"method": "status", "params": {}}
{"method": "conflicts", "params": {"workspace_a": "auth-refactor", "workspace_b": "payment-fix"}}
{"method": "subscribe", "params": {"events": ["score_change", "workspace_change"]}}
```

**Response format:**
```json
{"ok": true, "data": {...}}
{"ok": false, "error": "workspace not found: xyz"}
```

**Server-sent events (for subscribe):**
```json
{"event": "score_change", "data": {"pair": ["auth-refactor", "payment-fix"], "old": "yellow", "new": "red"}}
```

### Resource Limits

```toml
[daemon.limits]
max_warm_asts = 5000             # LRU count-based eviction (not byte-based)
max_worktrees = 20
analysis_timeout_ms = 30000      # Per-pair analysis timeout
max_file_size_kb = 1024          # Skip files larger than this for tree-sitter
circuit_breaker_threshold = 100  # Files per debounce window before full re-index
```

Tree-sitter ASTs are FFI wrappers around C-allocated memory. Rust's allocator cannot accurately measure their byte size. Count-based LRU (max_warm_asts) is reliable and sufficient.

---

## 5. Dependency Analysis Engine

The dependency layer is the hardest and most valuable. It catches conflicts that no other layer detects: workspace A changes a function signature that workspace B depends on, even though they touch completely different files.

### Module Resolution

Tree-sitter is a syntax parser. It extracts `import { foo } from './bar'` but cannot resolve `'./bar'` to a file path. Module resolution requires language-specific logic:

| Language | Resolution | Tooling |
|----------|------------|---------|
| TS/JS | tsconfig paths, baseUrl, barrel files, node_modules algorithm, conditional exports | `oxc_resolver` crate (production-quality, from the oxc project) |
| Rust | `mod`/`use` paths, `Cargo.toml` deps, `pub use` re-exports | `cargo metadata` for crate graph; tree-sitter for intra-crate `mod`/`use` |

`oxc_resolver` handles the full Node.js + TypeScript resolution algorithm. This is a solved problem — no custom resolver needed for TS/JS.

### Graph Construction and Maintenance

On daemon startup:
1. Parse all files in the base branch with tree-sitter
2. Extract imports/exports per file
3. Resolve imports to file paths using language-specific resolver
4. Build the `ImportGraph` (forward edges + reverse edges + export table)
5. Persist to SQLite for fast restart

On file change in worktree X:
1. Re-parse the file, extract new imports/exports
2. Diff against base graph's entry for this file
3. Update workspace X's `GraphOverlay`
4. If exports changed: walk `dependents` to find affected files
5. Cross-reference affected files against other workspaces' changed files

### Limitations

- Dynamic imports (`import()` with variables) are unresolvable statically. Flagged as "dependency analysis incomplete for this file."
- Barrel files with deep re-export chains add latency to graph traversal but are handled correctly by `oxc_resolver`.
- The initial graph build on a large repo (10k+ files) takes a few seconds. This happens once on daemon start and is cached.

---

## 6. Project Structure

### Repository Layout

```
grove/
├── Cargo.toml                    # Workspace root
├── Cargo.lock
├── .github/
│   └── workflows/
│       ├── ci.yml                # Build + test on Linux/macOS/Windows
│       └── release.yml           # Build release binaries per platform
├── crates/
│   ├── grove-lib/                # Pure analysis library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── git.rs            # Git operations (via gix)
│   │       ├── diff.rs           # File/hunk diff engine
│   │       ├── treesitter.rs     # Tree-sitter parsing, AST management
│   │       ├── symbols.rs        # Symbol extraction from ASTs
│   │       ├── imports.rs        # Import/export extraction
│   │       ├── graph.rs          # Import graph + overlay data structures
│   │       ├── scorer.rs         # Orthogonality scoring (all 5 layers)
│   │       ├── merge_order.rs    # Topological sort for merge sequence
│   │       ├── schema.rs         # Schema/config file detection
│   │       ├── fs.rs             # FileSystem trait
│   │       └── languages/
│   │           ├── mod.rs        # LanguageAnalyzer trait
│   │           ├── typescript.rs # TS/JS analyzer (uses oxc_resolver)
│   │           └── rust_lang.rs  # Rust analyzer
│   │
│   ├── grove-daemon/             # Daemon logic (LIB crate, not binary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # pub async fn run(config)
│   │       ├── state.rs          # DaemonState actor + message handling
│   │       ├── watcher.rs        # Filesystem watcher + debouncer + circuit breaker
│   │       ├── worker.rs         # Analysis worker pool
│   │       ├── socket.rs         # Unix socket server (NDJSON via LinesCodec)
│   │       ├── db.rs             # SQLite persistence layer
│   │       └── lifecycle.rs      # PID file, shutdown handling
│   │
│   ├── grove-cli/                # CLI logic (LIB crate, not binary)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs            # pub async fn run(args)
│   │       ├── client.rs         # Socket client to daemon
│   │       ├── commands/
│   │       │   ├── status.rs
│   │       │   ├── create.rs
│   │       │   ├── switch.rs
│   │       │   ├── conflicts.rs
│   │       │   ├── retire.rs
│   │       │   ├── rebase.rs
│   │       │   ├── merge_order.rs
│   │       │   ├── daemon.rs
│   │       │   ├── config.rs
│   │       │   └── init.rs       # Shell function generation
│   │       └── render.rs         # Terminal output formatting
│   │
│   └── grove/                    # THE single binary entry point
│       ├── Cargo.toml
│       └── src/
│           └── main.rs           # Dispatches to CLI or daemon mode
│
├── tests/
│   ├── integration/              # Full daemon + CLI integration tests
│   └── fixtures/                 # Test repositories
│
└── docs/
    └── plans/
```

### Crate Dependencies

```toml
# grove-lib
[dependencies]
gix = "0.76"
tree-sitter = "0.26"
tree-sitter-typescript = "0.23"
tree-sitter-rust = "0.24"
oxc_resolver = "11"
similar = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
petgraph = "0.8"

# grove-daemon
[dependencies]
grove-lib = { path = "../grove-lib" }
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }
notify = "8"
rusqlite = { version = "0.38", features = ["bundled"] }
ignore = "0.4"
tracing = "0.1"
tracing-subscriber = "0.3"

# grove-cli
[dependencies]
grove-lib = { path = "../grove-lib" }
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["net", "io-util"] }
tokio-util = { version = "0.7", features = ["codec"] }
colored = "3"
serde_json = "1"

# grove (root binary)
[dependencies]
grove-cli = { path = "../grove-cli" }
grove-daemon = { path = "../grove-daemon" }
daemonize = "0.5"
clap = { version = "4", features = ["derive"] }
tokio = { version = "1", features = ["full"] }
```

Note: versions reflect latest stable as of February 2026. Update to latest before implementation.

### Configuration (`.grove/config.toml`)

```toml
[general]
base_branch = "main"
editor = "code"
stale_threshold_days = 7

[daemon]
watch_interval_ms = 500
auto_start = true
ignore = [
    "node_modules",
    "target",
    "dist",
    "build",
    ".git/objects",
    ".git/lfs",
    "*.min.js",
    "*.map",
]
respect_gitignore = true   # Per-worktree .gitignore evaluation

[daemon.limits]
max_warm_asts = 5000
max_worktrees = 20
analysis_timeout_ms = 30000
max_file_size_kb = 1024
circuit_breaker_threshold = 100

[analysis]
enable_dependency_layer = true
schema_patterns = [
    "*.sql",
    "migrations/**",
    "package.json",
    "Cargo.toml",
    "go.mod",
    ".env*",
    "*.config.*",
    "routes/**",
]

[languages.typescript]
enabled = true
tsconfig_path = "tsconfig.json"

[languages.rust]
enabled = true
```

---

## 7. Testing Strategy

### grove-lib (unit tests)

- `InMemoryFileSystem` for all tests: deterministic, no disk I/O
- Test each analysis layer independently with crafted file pairs
- Property-based tests for the scorer: "disjoint file sets always score Green"
- Snapshot tests for symbol extraction per language
- Benchmark tests for the full pipeline on realistic file sets

### grove-daemon (integration tests)

- Spawn daemon in-process, communicate via socket protocol
- Temporary git repos created programmatically with `gix`
- Full cycle tests: create worktree, edit files, verify score changes
- Circuit breaker test: generate 500 file events, verify re-index mode
- Base ref change test: advance base branch, verify graph rebuild

### grove-cli (integration tests)

- Snapshot tests for terminal output formatting
- `--json` output schema validation
- Shell function generation tests for zsh, bash, fish

### End-to-end tests

- Create real git repos with multiple worktrees
- Run the compiled `grove` binary
- Verify all commands produce correct output
- Verify `grove retire` cleans up properly

### Distribution

- **cargo install grove**: standard Rust installation
- **GitHub Releases**: prebuilt binaries for x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin, x86_64-windows
- **Homebrew**: `brew install grove`

---

## 8. What Makes This Defensible

The worktree CRUD lifecycle is trivially copyable. The moat is:

1. **Symbol-level overlap detection** via tree-sitter AST analysis across divergent worktrees
2. **Dependency-level overlap detection** via a persistent, incrementally-maintained import graph with language-specific module resolution
3. **The base + overlay graph model** that correctly handles multiple divergent realities of the same codebase simultaneously
4. **The pluggable LanguageAnalyzer trait** that makes the system extensible without core changes

Everyone else is building prettier `git worktree list`. Grove is a merge conflict early warning system that happens to also manage worktrees.
