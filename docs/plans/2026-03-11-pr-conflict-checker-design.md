# PR Conflict Checker: Cross-PR Conflict Intelligence for Maintainers

## Overview

New mode for Grove that analyzes open pull requests for potential conflicts — not just textual merge conflicts, but symbol-level and dependency-level collisions. Runs as a GitHub Action, posts results as PR comments and maintainer-facing summaries.

This is an addition to Grove, not a replacement. Existing worktree, daemon, and TUI functionality remains unchanged.

## Architecture

Two new components. Meaningful refactoring of `grove-lib` and `grove-daemon`.

```
GitHub Action (JS/composite)            grove binary
┌──────────────────────────────┐        ┌──────────────────────────┐
│ Lists open PRs (GitHub API)  │        │ grove ci analyze         │
│ Fetches PR branches          │─stdin─▶│ Reads branch list        │
│ Pipes branch names           │        │ Ref-based diffs          │
│                              │◀stdout─│ Full pairwise analysis   │
│ Parses JSON output           │        │ JSON matrix output       │
│ Enriches with PR metadata    │        └──────────────────────────┘
│ Posts/updates PR comments    │                   │
└──────────────────────────────┘                   ▼
                                        ┌──────────────────────────┐
                                        │ grove-lib (refactored)   │
                                        │ + GitObjectFileSystem    │
                                        │ + shared graph builder   │
                                        │ + shared changeset build │
                                        │ + CI output DTOs         │
                                        └──────────────────────────┘
```

### Component 1: `grove ci analyze` command

New subcommand in `grove-cli`. Stateless, one-shot analysis — no daemon, no filesystem watching. Operates on the git repository in the current working directory.

**Bootstrap bypass:** The `grove ci` subcommand must be handled *before* the bootstrap fallthrough in `grove-cli/src/lib.rs`. Currently, every non-exempt command triggers `bootstrap::bootstrap()` which creates `.grove/`, updates git exclude, and spawns the daemon. The CI command must be carved out at the same level as `Init` and `Daemon Start` — it operates directly on the repo with no side effects on the checkout.

**Interface:**

```
grove ci analyze [--base main] [--timeout 30] [--disable-layer dependency] --refs-from-stdin
grove ci analyze [--base main] ref1 ref2 ... refN
```

`--refs-from-stdin` is the primary interface. The Action pipes ref specs (one per line) to stdin. Each line is either:
- A bare ref: `refs/remotes/origin/pr/42` — used as both the analysis identity and display label
- A labeled ref: `refs/remotes/origin/pr/42=PR #42 (feature/auth)` — ref before `=` is the analysis identity, text after `=` is the display label in output

Positional ref args exist for local debugging.

| Flag | Default | Description |
|------|---------|-------------|
| `--base` | `main` | Base branch to compute merge bases against |
| `--refs-from-stdin` | — | Read ref specs from stdin, one per line |
| `--timeout` | `30` | Per-pair analysis timeout in seconds |
| `--disable-layer` | — | Repeatable. Disable a specific layer (e.g. `--disable-layer dependency`) |

**Behavior:**

1. Read ref specs from stdin (or args), parsing optional `=label` suffix
2. For each ref, compute merge base against `--base` (default: `main`)
3. Extract changeset from git object store via ref-based diff (ref tip vs merge base)
4. Build base import graph once (enumerate all source files in the base branch tree via `gix` tree walking, filter by language extensions, parse with tree-sitter, extract imports/exports)
5. Build a `WorkspaceChangeset` per branch (changed files, hunks, symbols, export deltas)
6. Run pairwise scoring via `scorer::score_pair` + `compute_dependency_overlaps` across all branch combinations (all 5 layers by default)
7. Output full conflict matrix as JSON to stdout

**Identity model:** The canonical identity for each analysis unit is the **git ref**, not the branch name. Branch names are not unique across forks (two PRs can both be named `feature/auth`), but refs like `refs/remotes/origin/pr/42` are unique by construction. The analysis pipeline uses `WorkspaceId` (UUID) internally; the CI command generates deterministic synthetic UUIDs from the ref string (UUID v5, namespace = repo path). This keeps `grove-lib` types unchanged.

Display labels (human-readable names like `PR #42 (feature/auth)`) are provided separately via the `ref=label` input format and carried through to the output. If no label is provided, the ref string is used as the display label.

**CI output DTOs:** The JSON output format differs structurally from the internal types (`WorkspacePairAnalysis`, `Overlap`). Internal types use PascalCase scores, UUIDs, and serde's default tagged enum serialization. The CI output uses lowercase scores, display labels, and flat `{"type": "...", ...}` objects. A dedicated set of CI output structs handles the translation — they are *not* the same types with custom serialization. The CI command converts `Vec<WorkspacePairAnalysis>` into the output DTOs, replacing UUIDs with display labels (including nested fields like `changed_in` in dependency overlaps) via a `HashMap<WorkspaceId, String>` built at startup.

**Pairwise scaling:** For N branches, N*(N-1)/2 pairs are analyzed. The CLI itself does not cap branch count — it analyzes whatever it's given. The Action layer caps input at 50 branches by default (most recently updated first) via its `max-branches` input. This separation means the CLI is a correct tool for any input size, while the Action provides a sensible default for CI resource constraints.

**Output format (JSON):**

```json
{
  "base": "main",
  "refs": [
    {"ref": "refs/remotes/origin/pr/1", "label": "PR #1 (feature/auth)"},
    {"ref": "refs/remotes/origin/pr/2", "label": "PR #2 (fix/payment)"},
    {"ref": "refs/remotes/origin/pr/3", "label": "PR #3 (feature/onboard)"}
  ],
  "pairs": [
    {
      "a": "PR #1 (feature/auth)",
      "b": "PR #2 (fix/payment)",
      "score": "red",
      "overlaps": [
        {
          "type": "file",
          "path": "payment/checkout.ts",
          "a_change": "modified",
          "b_change": "modified"
        },
        {
          "type": "hunk",
          "path": "payment/types.ts",
          "a_range": [12, 30],
          "b_range": [18, 45],
          "overlap_lines": 12
        },
        {
          "type": "symbol",
          "path": "payment/checkout.ts",
          "symbol": "processPayment",
          "a_modification": "adds auth token parameter",
          "b_modification": "changes return type"
        },
        {
          "type": "dependency",
          "changed_in": "PR #2 (fix/payment)",
          "changed_file": "payment/checkout.ts",
          "changed_export": "processPayment (signature changed)",
          "affected_file": "onboard/payment-step.ts",
          "affected_usages": ["line 47"]
        },
        {
          "type": "schema",
          "category": "package_dep",
          "a_file": "package.json",
          "b_file": "package.json",
          "detail": "both modify dependencies"
        }
      ]
    },
    {
      "a": "PR #1 (feature/auth)",
      "b": "PR #3 (feature/onboard)",
      "score": "yellow",
      "overlaps": []
    },
    {
      "a": "PR #2 (fix/payment)",
      "b": "PR #3 (feature/onboard)",
      "score": "black",
      "overlaps": []
    }
  ],
  "merge_order": {
    "status": "complete",
    "sequenced": ["PR #3 (feature/onboard)", "PR #1 (feature/auth)", "PR #2 (fix/payment)"],
    "independent": []
  },
  "skipped": []
}
```

Score values are lowercase strings: `"green"`, `"yellow"`, `"red"`, `"black"` (custom serde serialization). All five overlap types are represented. The `merge_order` object separates sequenced branches from independent ones. The `skipped` array lists branches that were skipped (nonexistent, already merged) with reasons.

**Merge order trustworthiness:** The `merge_order.status` field is one of:
- `"complete"` — all pairs analyzed successfully, no cycles detected. Merge order is fully trusted.
- `"cycle"` — all pairs analyzed, but the dependency graph has a cycle (`MergeSequence.has_cycle == true`). The order is an arbitrary fallback, not a topological sort. The `merge_order.cycle_note` field explains this.
- `"partial"` — one or more pairs timed out. Merge order is computed from available data but may be wrong — a missing pair silently becomes "no edge" (independent), which is a false-safe. The `merge_order.incomplete_pairs` array lists which pairs lacked data.
- `"unavailable"` — too many pairs timed out to produce a meaningful order.

The Action should display a warning for any status other than `"complete"` and must not present a partial or cycle-fallback order as reliable guidance.

**Analysis depth:** All 5 layers (file, hunk, symbol, dependency, schema) enabled by default. The dependency layer is the most expensive (requires full base graph construction) but provides the highest-value signal. Layers can be disabled via `--disable-layer` for repos where the cost is prohibitive. No config file for v1.

### Component 2: GitHub Action wrapper

Lives in the Grove repo (e.g. `action/` directory). Published for use as `uses: NathanDrake2406/grove@v1`.

**Two trigger modes:**

#### PR-triggered (on `pull_request` open/synchronize/rebase)

1. Install Grove binary from GitHub Releases
2. Checkout repo with full history (`fetch-depth: 0`)
3. Query GitHub API for all open PRs targeting the same base branch
4. **Fetch all PR head refs into stable local refs.** For each PR, run `git fetch origin refs/pull/<n>/head:refs/remotes/origin/pr/<n>`. This creates a stable local ref that `grove ci analyze` can diff against. A bare `git fetch origin <ref>` only updates `FETCH_HEAD` and would be overwritten by subsequent fetches.
5. Pipe labeled ref specs to `grove ci analyze --refs-from-stdin`, one per line: `refs/remotes/origin/pr/<n>=PR #<n> (<branch_name>)`
6. Parse JSON, find pairs involving the triggering PR's label
7. Post/update a bot comment on the triggering PR:
   - Which other open PRs it conflicts with (with PR numbers, links, authors)
   - Conflict severity and overlap details
   - Suggested merge order (with warning if status is not `complete`)
8. If no conflicts: configurable — post "all clear" or stay silent

#### Scheduled (on `schedule`, e.g. cron)

1. Same install + full checkout
2. Query all open PRs targeting the base branch
3. **Fetch all PR head refs into stable local refs** (same as PR-triggered step 4)
4. Pipe labeled ref specs and run full matrix via `grove ci analyze`
5. Post/update a dedicated issue (identified by a `grove-ci-matrix` label) with the complete conflict matrix
6. Optionally comment on individual PRs whose conflict status changed since last run

On first scheduled run, the Action creates the tracking issue. On subsequent runs, it finds and updates the existing issue by label.

**Comment idempotency:** The Action finds and updates its own existing comment (by a marker like `<!-- grove-ci -->`) rather than posting new comments on every run.

**Action inputs:**

```yaml
inputs:
  base-branch:
    description: "Base branch to analyze against"
    default: "main"
  disable-layers:
    description: "Comma-separated layers to disable (e.g. 'dependency,schema')"
    default: ""
  comment-on-clean:
    description: "Post a comment when no conflicts are found"
    default: "false"
  grove-version:
    description: "Grove version to install (tag from GitHub Releases, e.g. 'v0.4.0')"
    default: "latest"
  max-branches:
    description: "Maximum number of PR branches to analyze (most recently updated first)"
    default: "50"
```

**Binary installation:** The Action downloads the pre-built `x86_64-unknown-linux-gnu` binary from GitHub Releases (Actions run on `ubuntu-latest` by default). The `grove-version: latest` default resolves to the most recent GitHub Release tag at runtime.

### Component 3: `grove-lib` addition — ref-based diff extraction

Currently, Grove computes changesets by diffing a live worktree's filesystem against the base. For CI, there's no worktree on disk — branches exist only as git refs.

**New capability:** Extract a changeset (changed files, hunks, symbol modifications) directly from the git object store by comparing two refs. Uses `gix` to walk the tree diff between merge base and branch tip, then feeds file contents from the object store into the existing tree-sitter + analysis pipeline via the `FileSystem` trait.

**Implementation: `GitObjectFileSystem`**

A new `FileSystem` trait implementation that reads from git objects instead of disk.

```rust
struct GitObjectFileSystem {
    repo: gix::Repository,
    commit: gix::ObjectId,  // The tree to read from (base or branch tip)
}
```

Key design decisions:

- **Paths are repo-relative** throughout `grove-lib`. The `FileSystem` trait already works with repo-relative `Path` references (confirmed in `InMemoryFileSystem` tests: `PathBuf::from("src/main.rs")`). `GitObjectFileSystem` maps these to git tree entries naturally. There is no `MmapFileSystem` or `DiskFileSystem` — the daemon currently reads files via `std::fs::read` and `GitRepo` directly, not through the `FileSystem` trait. No disk-backed `FileSystem` impl is added in this work.
- **`list_dir` returns direct children** of a tree entry, matching the existing trait contract. Recursive file discovery for base graph construction is handled by the caller (tree walking via `gix::traverse::tree`), not by `list_dir`.
- **`read_file` resolves a path** through the commit's tree object to a blob, returning its raw contents. Size filtering and binary detection remain the caller's responsibility (as they are today in `worker.rs:395`), not the `FileSystem` impl's.
- **One instance for base graph construction**: a `GitObjectFileSystem` pinned to the base branch commit. Used to enumerate and read files for building the `ImportGraph`. The daemon's `build_base_graph_from_workspace` already reads from git objects via subprocess (`git show base_ref:path`); the refactored version replaces that with `GitObjectFileSystem`, unifying both callers. `FileSystem` is **not** used for changeset extraction — that operates on raw byte pairs provided by the caller (see "Changeset extraction refactor" below).

**Base graph construction orchestration:**

The CI command orchestrates building the base import graph:
1. Walk the base branch tree via `gix::traverse::tree::breadth_first`
2. Filter files by language extensions (`.ts`, `.tsx`, `.js`, `.rs`, etc.)
3. Read each file via `GitObjectFileSystem`, parse with tree-sitter
4. Extract imports/exports via `LanguageAnalyzer`
5. Build the `ImportGraph`

This is the same logic the daemon performs on startup, extracted into a reusable function in `grove-lib` that accepts any `FileSystem` implementation. It must live in `grove-lib` because `grove-cli` depends on `grove-lib` but not `grove-daemon`. The daemon's existing `build_base_graph_from_workspace` in `grove-daemon/src/worker.rs` should be refactored to call this shared function.

**Required `gix` features:** `gix-object`, `gix-traverse`, `gix-diff` (for tree-to-tree diff). These are already transitively available through the existing `gix` dependency.

**Changeset extraction refactor:**

The current `extract_changeset` in `grove-daemon/src/worker.rs:340` is tightly coupled to the daemon's context: it reads the NEW side from disk via `std::fs::read` (to capture uncommitted working tree changes), uses `GitRepo` for OLD-side blob access, and assumes a live worktree exists.

Two layers need separation:

1. **Pure content-to-changeset logic** (moves to `grove-lib`): Given a list of `(path, change_type, old_bytes, new_bytes)` tuples, compute hunks, extract modified symbols, compute export deltas, and produce a `WorkspaceChangeset`. This is pure — no I/O, no `FileSystem` needed. Both the daemon and CI command call this with different content sources.

2. **Content sourcing** (stays in callers):
   - **Daemon**: reads OLD side from git objects (via `GitRepo`/`gix`), NEW side from disk (`std::fs::read`) to capture uncommitted changes. This is daemon-specific behavior that CI doesn't need.
   - **CI command**: reads both OLD and NEW sides from git objects via `GitObjectFileSystem`. No disk reads.

The `FileSystem` trait is used for base graph construction (enumerating and reading files from a commit tree). It is *not* used for changeset extraction, which operates on raw byte pairs.

This is the largest refactoring task — it moves the pure core of `grove-daemon/src/worker.rs` (hunk computation, symbol extraction, export delta computation) into `grove-lib` as content-in/changeset-out functions.

## What stays unchanged (behavior)

Existing behavior is preserved. No user-visible changes to worktree management, daemon, TUI, or CLI commands.

**Internally refactored** (same behavior, new location):
- `build_base_graph_from_workspace` moves from `grove-daemon/src/worker.rs` to `grove-lib` as a `FileSystem`-generic function. The daemon calls the new shared function.
- `extract_changeset` core logic (hunk computation, symbol extraction, export deltas) moves to `grove-lib`. The daemon's version becomes a thin wrapper providing disk-based file access.

**Unchanged:**
- `grove-daemon` (watcher, state actor, socket, db) — behavior preserved, calls refactored functions
- `grove-cli` existing commands (status, conflicts, create, retire, etc.)
- `grove-tui` (terminal dashboard)
- Worktree management functionality
- Daemon auto-start / zero-config bootstrap

## Error handling

- Branch that no longer exists (force-pushed away): skip it, note in output
- Branch with no diff against base (already merged): skip it
- Tree-sitter parse failure on a file: degrade gracefully, report file-level overlap only
- Analysis timeout per pair: configurable via `--timeout` flag, default 30s. Timed-out pairs reported in output with `"score": null` and `"timed_out": true` — timeout is not a score, it's an operational failure. The `OrthogonalityScore` enum stays unchanged
- GitHub API rate limits: Action handles retries with backoff
- Large repos (base graph construction): tree walking and parsing is bounded by language file extensions — non-source files are skipped entirely. For very large repos, disabling the dependency layer via `--disable-layer dependency` skips base graph construction altogether

## Testing strategy

**`grove ci analyze` (integration tests):**
- Create a temporary git repo with multiple branches programmatically
- Run `grove ci analyze` against the branches
- Assert JSON output contains correct scores and overlaps
- Test `--refs-from-stdin` path (bare refs and labeled `ref=label` format)
- Test with branches that have no overlap (all green)
- Test with branches that have dependency-level conflicts (black)

**Merge order trust contract (integration tests):**
- All pairs green → `merge_order.status` is `"complete"`, all branches independent
- Normal ordering constraints → `merge_order.status` is `"complete"`, order respects hints
- Cyclic dependency graph → `merge_order.status` is `"cycle"`, `cycle_note` present
- One pair times out → `merge_order.status` is `"partial"`, `incomplete_pairs` lists the timed-out pair, order still computed from available data
- All pairs time out → `merge_order.status` is `"unavailable"`
- Action integration: verify the Action renders a warning for any non-`complete` status

**`GitObjectFileSystem` (unit tests in `grove-lib`):**
- Read files from git objects, verify content matches
- Return `FsError::NotFound` for missing paths
- Return raw bytes without filtering (size/binary filtering is the caller's responsibility, matching the existing `FileSystem` trait contract)
- `list_dir` returns direct children of a tree entry

**GitHub Action (manual testing for v1):**
- Test on a real repo with open PRs
- Verify comment posting, updating, and idempotency
- Verify scheduled run produces correct matrix

## Future considerations (not v1)

- Docker container action for faster cold starts
- `.grove-ci.toml` config file for per-repo layer configuration
- GitLab / Bitbucket support via platform trait
- Caching the base import graph between Action runs
- `--format markdown` for local human-readable output
