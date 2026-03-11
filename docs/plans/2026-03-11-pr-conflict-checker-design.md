# PR Conflict Checker: Cross-PR Conflict Intelligence for Maintainers

## Overview

New mode for Grove that analyzes open pull requests for potential conflicts — not just textual merge conflicts, but symbol-level and dependency-level collisions. Runs as a GitHub Action, posts results as PR comments and maintainer-facing summaries.

This is an addition to Grove, not a replacement. Existing worktree, daemon, and TUI functionality remains unchanged.

## Architecture

Two new components. One change to `grove-lib`.

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
                                        │ grove-lib (minimal delta)│
                                        │ + ref-based diff extract │
                                        └──────────────────────────┘
```

### Component 1: `grove ci analyze` command

New subcommand in `grove-cli`. Stateless, one-shot analysis — no daemon, no filesystem watching. Operates on the git repository in the current working directory.

**Interface:**

```
grove ci analyze [--base main] [--timeout 30] [--disable-layer dependency] --branches-from-stdin
grove ci analyze [--base main] branch1 branch2 ... branchN
```

`--branches-from-stdin` is the primary interface. The Action pipes branch names (one per line) to stdin. Positional branch args exist for local debugging.

| Flag | Default | Description |
|------|---------|-------------|
| `--base` | `main` | Base branch to compute merge bases against |
| `--branches-from-stdin` | — | Read branch names from stdin, one per line |
| `--timeout` | `30` | Per-pair analysis timeout in seconds |
| `--disable-layer` | — | Repeatable. Disable a specific layer (e.g. `--disable-layer dependency`) |

**Behavior:**

1. Read branch list from stdin (or args)
2. For each branch, compute merge base against `--base` (default: `main`)
3. Extract changeset from git object store via ref-based diff (branch tip vs merge base)
4. Build base import graph once (enumerate all source files in the base branch tree via `gix` tree walking, filter by language extensions, parse with tree-sitter, extract imports/exports)
5. Build a `GraphOverlay` per branch
6. Run pairwise scoring across all branch combinations (all 5 layers by default)
7. Output full conflict matrix as JSON to stdout

**Identity mapping:** The analysis pipeline uses `WorkspaceId` (UUID) internally. The CI command generates deterministic synthetic UUIDs from branch names (UUID v5, namespace = repo path). The JSON output maps back to branch name strings — UUIDs never leak into the output, including nested fields like `changed_in` inside dependency overlaps. The CI command builds a `HashMap<WorkspaceId, String>` (UUID -> branch name) at startup and uses it to translate all output. This keeps the `grove-lib` analysis types unchanged.

**Pairwise scaling:** For N branches, N*(N-1)/2 pairs are analyzed. For large PR counts, this grows quadratically. v1 does not cap this — repos with 50+ open PRs against the same base branch are an edge case. If needed, a `--max-branches` flag can be added later.

**Output format (JSON):**

```json
{
  "base": "main",
  "branches": ["feature/auth", "fix/payment", "feature/onboard"],
  "pairs": [
    {
      "a": "feature/auth",
      "b": "fix/payment",
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
          "changed_in": "fix/payment",
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
      "a": "feature/auth",
      "b": "feature/onboard",
      "score": "yellow",
      "overlaps": []
    },
    {
      "a": "fix/payment",
      "b": "feature/onboard",
      "score": "black",
      "overlaps": []
    }
  ],
  "merge_order": {
    "sequenced": ["feature/onboard", "feature/auth", "fix/payment"],
    "independent": []
  },
  "skipped": []
}
```

Score values are lowercase strings: `"green"`, `"yellow"`, `"red"`, `"black"` (custom serde serialization). All five overlap types are represented. The `merge_order` object separates sequenced branches from independent ones. The `skipped` array lists branches that were skipped (nonexistent, already merged) with reasons.

**Analysis depth:** All 5 layers (file, hunk, symbol, dependency, schema) enabled by default. The dependency layer is the most expensive (requires full base graph construction) but provides the highest-value signal. Layers can be disabled via `--disable-layer` for repos where the cost is prohibitive. No config file for v1.

### Component 2: GitHub Action wrapper

Lives in the Grove repo (e.g. `action/` directory). Published for use as `uses: NathanDrake2406/grove@v1`.

**Two trigger modes:**

#### PR-triggered (on `pull_request` open/synchronize/rebase)

1. Install Grove binary from GitHub Releases
2. Checkout repo with full history (`fetch-depth: 0`)
3. Query GitHub API for all open PRs targeting the same base branch
4. Pipe branch names to `grove ci analyze --branches-from-stdin`
5. Parse JSON, find pairs involving the triggering PR
6. Post/update a bot comment on the triggering PR:
   - Which other open PRs it conflicts with (with PR numbers, links, authors)
   - Conflict severity and overlap details
   - Suggested merge order
7. If no conflicts: configurable — post "all clear" or stay silent

#### Scheduled (on `schedule`, e.g. cron)

1. Same install + full checkout
2. Query all open PRs targeting the base branch
3. Run full matrix via `grove ci analyze`
4. Post/update a dedicated issue (identified by a `grove-ci-matrix` label) with the complete conflict matrix
5. Optionally comment on individual PRs whose conflict status changed since last run

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

- **Paths are repo-relative** throughout `grove-lib`. The `FileSystem` trait already works with repo-relative `Path` references. `GitObjectFileSystem` maps these to git tree entries naturally. The existing `MmapFileSystem` converts repo-relative paths to absolute internally.
- **`list_dir` returns direct children** of a tree entry, matching the existing trait contract. Recursive file discovery for base graph construction is handled by the caller (tree walking via `gix::traverse::tree`), not by `list_dir`.
- **`read_file` resolves a path** through the commit's tree object to a blob, returning its contents. Binary files and files exceeding `max_file_size_kb` return an error.
- **Two instances per analysis**: one `GitObjectFileSystem` pinned to the base branch commit (for base graph construction), one per branch tip (for overlay computation). The analysis pipeline doesn't know the difference — it just calls `FileSystem` methods.

**Base graph construction orchestration:**

The CI command orchestrates building the base import graph:
1. Walk the base branch tree via `gix::traverse::tree::breadth_first`
2. Filter files by language extensions (`.ts`, `.tsx`, `.js`, `.rs`, etc.)
3. Read each file via `GitObjectFileSystem`, parse with tree-sitter
4. Extract imports/exports via `LanguageAnalyzer`
5. Build the `ImportGraph`

This is the same logic the daemon performs on startup, extracted into a reusable function in `grove-lib` that accepts any `FileSystem` implementation. It must live in `grove-lib` because `grove-cli` depends on `grove-lib` but not `grove-daemon`. The daemon's existing `build_base_graph_from_workspace` in `grove-daemon/src/worker.rs` should be refactored to call this shared function.

**Required `gix` features:** `gix-object`, `gix-traverse`, `gix-diff` (for tree-to-tree diff). These are already transitively available through the existing `gix` dependency.

**These are the only changes to `grove-lib`.**

## What stays unchanged

- `grove-lib` analysis pipeline (scorer, graph, overlays, languages)
- `grove-daemon` (watcher, state actor, socket, db)
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
- Test `--branches-from-stdin` path
- Test with branches that have no overlap (all green)
- Test with branches that have dependency-level conflicts (black)

**`GitObjectFileSystem` (unit tests in `grove-lib`):**
- Read files from git objects, verify content matches
- Handle missing files, binary files, files exceeding size limit

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
