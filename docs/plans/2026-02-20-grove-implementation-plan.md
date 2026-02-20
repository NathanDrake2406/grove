# Grove Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a CLI tool that manages git worktrees with cross-worktree conflict intelligence — detecting file, hunk, symbol, dependency, and schema overlaps between parallel workstreams.

**Architecture:** Rust workspace with 4 crates: `grove-lib` (pure analysis library), `grove-daemon` (background watcher + state actor), `grove-cli` (command-line interface), and `grove` (single multiplexed binary entry point). Daemon communicates via NDJSON over Unix socket. Actor model concurrency with `tokio::mpsc`.

**Tech Stack:** Rust, gix (gitoxide), tree-sitter, oxc_resolver, tokio, notify, rusqlite, petgraph, clap, similar

**Design Doc:** `docs/plans/2026-02-20-grove-design.md` — read this for full architectural context.

---

## Phase 1: Project Scaffolding

### Task 1: Initialize Cargo Workspace

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/grove-lib/Cargo.toml`
- Create: `crates/grove-lib/src/lib.rs`
- Create: `crates/grove-daemon/Cargo.toml`
- Create: `crates/grove-daemon/src/lib.rs`
- Create: `crates/grove-cli/Cargo.toml`
- Create: `crates/grove-cli/src/lib.rs`
- Create: `crates/grove/Cargo.toml`
- Create: `crates/grove/src/main.rs`
- Create: `.gitignore`

**Step 1: Create workspace root Cargo.toml**

```toml
# Cargo.toml
[workspace]
resolver = "2"
members = [
    "crates/grove-lib",
    "crates/grove-daemon",
    "crates/grove-cli",
    "crates/grove",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
repository = "https://github.com/TODO/grove"

[workspace.dependencies]
# Analysis
gix = "0.76"
tree-sitter = "0.26"
tree-sitter-typescript = "0.23"
tree-sitter-rust = "0.24"
oxc_resolver = "11"
similar = "2"
petgraph = "0.8"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Error handling
thiserror = "2"

# Async runtime
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }

# Filesystem
notify = "8"
ignore = "0.4"

# Database
rusqlite = { version = "0.38", features = ["bundled"] }

# CLI
clap = { version = "4", features = ["derive"] }
colored = "3"

# Daemon
daemonize = "0.5"

# Observability
tracing = "0.1"
tracing-subscriber = "0.3"

# Time
chrono = { version = "0.4", features = ["serde"] }

# IDs
uuid = { version = "1", features = ["v4", "serde"] }

# Bytes
bytes = "1"
```

**Step 2: Create grove-lib crate**

```toml
# crates/grove-lib/Cargo.toml
[package]
name = "grove-lib"
version.workspace = true
edition.workspace = true

[dependencies]
gix = { workspace = true }
tree-sitter = { workspace = true }
tree-sitter-typescript = { workspace = true }
tree-sitter-rust = { workspace = true }
oxc_resolver = { workspace = true }
similar = { workspace = true }
petgraph = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
bytes = { workspace = true }
```

```rust
// crates/grove-lib/src/lib.rs
pub mod fs;
pub mod types;

pub use types::*;
```

**Step 3: Create grove-daemon crate**

```toml
# crates/grove-daemon/Cargo.toml
[package]
name = "grove-daemon"
version.workspace = true
edition.workspace = true

[dependencies]
grove-lib = { path = "../grove-lib" }
tokio = { workspace = true }
tokio-util = { workspace = true }
notify = { workspace = true }
ignore = { workspace = true }
rusqlite = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
```

```rust
// crates/grove-daemon/src/lib.rs
pub async fn run() {
    tracing::info!("grove daemon starting");
}
```

**Step 4: Create grove-cli crate**

```toml
# crates/grove-cli/Cargo.toml
[package]
name = "grove-cli"
version.workspace = true
edition.workspace = true

[dependencies]
grove-lib = { path = "../grove-lib" }
clap = { workspace = true }
tokio = { workspace = true }
tokio-util = { workspace = true }
colored = { workspace = true }
serde_json = { workspace = true }
serde = { workspace = true }
```

```rust
// crates/grove-cli/src/lib.rs
pub async fn run() {
    println!("grove cli");
}
```

**Step 5: Create grove binary crate**

```toml
# crates/grove/Cargo.toml
[package]
name = "grove"
version.workspace = true
edition.workspace = true

[[bin]]
name = "grove"
path = "src/main.rs"

[dependencies]
grove-cli = { path = "../grove-cli" }
grove-daemon = { path = "../grove-daemon" }
daemonize = { workspace = true }
clap = { workspace = true }
tokio = { workspace = true }
```

```rust
// crates/grove/src/main.rs
fn main() {
    println!("grove v{}", env!("CARGO_PKG_VERSION"));
}
```

**Step 6: Create .gitignore**

```gitignore
/target
Cargo.lock
.grove/
*.swp
*.swo
.DS_Store
```

Note: `Cargo.lock` should be committed for binary crates. Remove it from `.gitignore` after the first successful build.

**Step 7: Build and verify**

Run: `cargo build --workspace`
Expected: Successful compilation with no errors.

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: initialize cargo workspace with 4-crate structure"
```

---

## Phase 2: Core Types (grove-lib)

### Task 2: Define foundational types

**Files:**
- Create: `crates/grove-lib/src/types.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Write types module with all core data structures**

```rust
// crates/grove-lib/src/types.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

// === Identifiers ===

pub type WorkspaceId = Uuid;
pub type CommitHash = String;
pub type FileId = PathBuf;

// === Workspace ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub branch: String,
    pub path: PathBuf,
    pub base_ref: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub metadata: WorkspaceMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceMetadata {
    pub description: Option<String>,
    pub issue_url: Option<String>,
    pub pr_url: Option<String>,
}

// === Change Analysis ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceChangeset {
    pub workspace_id: WorkspaceId,
    pub merge_base: CommitHash,
    pub changed_files: Vec<FileChange>,
    pub commits_ahead: u32,
    pub commits_behind: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub hunks: Vec<Hunk>,
    pub symbols_modified: Vec<Symbol>,
    pub exports_changed: Vec<ExportDelta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hunk {
    pub old_start: u32,
    pub old_lines: u32,
    pub new_start: u32,
    pub new_lines: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

impl LineRange {
    pub fn overlaps(&self, other: &LineRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    pub fn distance(&self, other: &LineRange) -> u32 {
        if self.overlaps(other) {
            0
        } else if self.end < other.start {
            other.start - self.end
        } else {
            self.start - other.end
        }
    }
}

// === Symbols ===

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub range: LineRange,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Class,
    Interface,
    TypeAlias,
    Enum,
    Constant,
    Variable,
    Method,
    Struct,
    Trait,
    Impl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportDelta {
    Added(Symbol),
    Removed(Symbol),
    SignatureChanged {
        symbol_name: String,
        old: Signature,
        new: Signature,
    },
}

// === Imports ===

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    pub source: String,
    pub symbols: Vec<ImportedSymbol>,
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ImportedSymbol {
    pub name: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportedSymbol {
    pub name: String,
    pub kind: SymbolKind,
    pub signature: Option<String>,
}

// === Location ===

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub file: PathBuf,
    pub line: u32,
    pub column: u32,
}

// === Orthogonality Analysis ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspacePairAnalysis {
    pub workspace_a: WorkspaceId,
    pub workspace_b: WorkspaceId,
    pub score: OrthogonalityScore,
    pub overlaps: Vec<Overlap>,
    pub merge_order_hint: MergeOrder,
    pub last_computed: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OrthogonalityScore {
    Green,
    Yellow,
    Red,
    Black,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Overlap {
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
        symbol_name: String,
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
        category: SchemaCategory,
        a_file: PathBuf,
        b_file: PathBuf,
        detail: String,
    },
}

impl Overlap {
    pub fn severity(&self) -> OrthogonalityScore {
        match self {
            Overlap::File { .. } => OrthogonalityScore::Yellow,
            Overlap::Hunk { distance, .. } => {
                if *distance == 0 {
                    OrthogonalityScore::Red
                } else {
                    OrthogonalityScore::Yellow
                }
            }
            Overlap::Symbol { .. } => OrthogonalityScore::Red,
            Overlap::Dependency { .. } => OrthogonalityScore::Black,
            Overlap::Schema { .. } => OrthogonalityScore::Yellow,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaCategory {
    Migration,
    PackageDep,
    EnvConfig,
    Route,
    CI,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeOrder {
    AFirst,
    BFirst,
    Either,
    NeedsCoordination,
}
```

**Step 2: Update lib.rs**

```rust
// crates/grove-lib/src/lib.rs
pub mod fs;
pub mod types;

pub use types::*;
```

**Step 3: Build and verify**

Run: `cargo build -p grove-lib`
Expected: Compiles with no errors.

**Step 4: Write tests for LineRange**

```rust
// Add to bottom of crates/grove-lib/src/types.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_range_overlaps_when_intersecting() {
        let a = LineRange { start: 10, end: 30 };
        let b = LineRange { start: 20, end: 40 };
        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
    }

    #[test]
    fn line_range_no_overlap_when_disjoint() {
        let a = LineRange { start: 10, end: 20 };
        let b = LineRange { start: 30, end: 40 };
        assert!(!a.overlaps(&b));
        assert!(!b.overlaps(&a));
    }

    #[test]
    fn line_range_distance_when_disjoint() {
        let a = LineRange { start: 10, end: 20 };
        let b = LineRange { start: 25, end: 40 };
        assert_eq!(a.distance(&b), 5);
        assert_eq!(b.distance(&a), 5);
    }

    #[test]
    fn line_range_distance_zero_when_overlapping() {
        let a = LineRange { start: 10, end: 30 };
        let b = LineRange { start: 20, end: 40 };
        assert_eq!(a.distance(&b), 0);
    }

    #[test]
    fn overlap_severity_levels() {
        assert_eq!(
            Overlap::File {
                path: PathBuf::from("a.ts"),
                a_change: ChangeType::Modified,
                b_change: ChangeType::Modified,
            }
            .severity(),
            OrthogonalityScore::Yellow
        );

        assert_eq!(
            Overlap::Hunk {
                path: PathBuf::from("a.ts"),
                a_range: LineRange { start: 10, end: 20 },
                b_range: LineRange { start: 15, end: 25 },
                distance: 0,
            }
            .severity(),
            OrthogonalityScore::Red
        );

        assert_eq!(
            Overlap::Symbol {
                path: PathBuf::from("a.ts"),
                symbol_name: "foo".into(),
                a_modification: "changed return type".into(),
                b_modification: "added parameter".into(),
            }
            .severity(),
            OrthogonalityScore::Red
        );
    }

    #[test]
    fn orthogonality_score_ordering() {
        assert!(OrthogonalityScore::Green < OrthogonalityScore::Yellow);
        assert!(OrthogonalityScore::Yellow < OrthogonalityScore::Red);
        assert!(OrthogonalityScore::Red < OrthogonalityScore::Black);
    }
}
```

**Step 5: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 6: Commit**

```bash
git add crates/grove-lib/src/types.rs crates/grove-lib/src/lib.rs
git commit -m "feat: define core data types for workspace, changeset, overlap, and scoring"
```

---

### Task 3: Define FileSystem trait and implementations

**Files:**
- Create: `crates/grove-lib/src/fs.rs`

**Step 1: Write the FileSystem trait with InMemoryFileSystem**

```rust
// crates/grove-lib/src/fs.rs
use bytes::Bytes;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("file not found: {0}")]
    NotFound(PathBuf),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub trait FileSystem: Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError>;
    fn exists(&self, path: &Path) -> bool;
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError>;
}

/// In-memory filesystem for testing. Deterministic, no disk I/O.
#[derive(Debug, Default, Clone)]
pub struct InMemoryFileSystem {
    files: HashMap<PathBuf, Vec<u8>>,
}

impl InMemoryFileSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) {
        self.files.insert(path.into(), content.into());
    }
}

impl FileSystem for InMemoryFileSystem {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError> {
        self.files
            .get(path)
            .map(|data| Bytes::copy_from_slice(data))
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let prefix = if path.to_string_lossy().ends_with('/') {
            path.to_path_buf()
        } else {
            PathBuf::from(format!("{}/", path.display()))
        };

        let mut entries: Vec<PathBuf> = self
            .files
            .keys()
            .filter(|p| {
                if let Ok(rest) = p.strip_prefix(path) {
                    // Direct children only (no nested path separators)
                    rest.components().count() == 1
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        entries.sort();
        Ok(entries)
    }
}

/// Memory-mapped filesystem for production use.
pub struct MmapFileSystem;

impl FileSystem for MmapFileSystem {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError> {
        let data = std::fs::read(path)?;
        Ok(Bytes::from(data))
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            entries.push(entry?.path());
        }
        entries.sort();
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_fs_read_existing_file() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("src/main.rs"), b"fn main() {}".to_vec());

        let content = fs.read_file(Path::new("src/main.rs")).unwrap();
        assert_eq!(&content[..], b"fn main() {}");
    }

    #[test]
    fn in_memory_fs_read_missing_file() {
        let fs = InMemoryFileSystem::new();
        let result = fs.read_file(Path::new("missing.rs"));
        assert!(result.is_err());
    }

    #[test]
    fn in_memory_fs_exists() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("a.rs"), b"".to_vec());

        assert!(fs.exists(Path::new("a.rs")));
        assert!(!fs.exists(Path::new("b.rs")));
    }

    #[test]
    fn in_memory_fs_list_dir() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("src/a.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("src/b.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("src/nested/c.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("other/d.rs"), b"".to_vec());

        let entries = fs.list_dir(Path::new("src")).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&PathBuf::from("src/a.rs")));
        assert!(entries.contains(&PathBuf::from("src/b.rs")));
    }
}
```

**Step 2: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 3: Commit**

```bash
git add crates/grove-lib/src/fs.rs
git commit -m "feat: add FileSystem trait with InMemoryFileSystem and MmapFileSystem"
```

---

## Phase 3: Diff Engine

### Task 4: File-level overlap detection

**Files:**
- Create: `crates/grove-lib/src/diff.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Write failing test for file overlap detection**

```rust
// crates/grove-lib/src/diff.rs
use crate::types::*;
use std::collections::HashSet;
use std::path::PathBuf;

/// Detect files modified in both changesets.
pub fn compute_file_overlaps(a: &WorkspaceChangeset, b: &WorkspaceChangeset) -> Vec<Overlap> {
    let a_paths: HashSet<&PathBuf> = a.changed_files.iter().map(|f| &f.path).collect();

    b.changed_files
        .iter()
        .filter(|f| a_paths.contains(&f.path))
        .map(|b_file| {
            let a_file = a
                .changed_files
                .iter()
                .find(|f| f.path == b_file.path)
                .unwrap();
            Overlap::File {
                path: b_file.path.clone(),
                a_change: a_file.change_type,
                b_change: b_file.change_type,
            }
        })
        .collect()
}

/// Detect overlapping or nearby hunks in files modified by both changesets.
pub fn compute_hunk_overlaps(
    a: &WorkspaceChangeset,
    b: &WorkspaceChangeset,
    proximity_threshold: u32,
) -> Vec<Overlap> {
    let mut overlaps = Vec::new();

    for a_file in &a.changed_files {
        if let Some(b_file) = b.changed_files.iter().find(|f| f.path == a_file.path) {
            for a_hunk in &a_file.hunks {
                let a_range = LineRange {
                    start: a_hunk.new_start,
                    end: a_hunk.new_start + a_hunk.new_lines.saturating_sub(1),
                };
                for b_hunk in &b_file.hunks {
                    let b_range = LineRange {
                        start: b_hunk.new_start,
                        end: b_hunk.new_start + b_hunk.new_lines.saturating_sub(1),
                    };
                    let distance = a_range.distance(&b_range);
                    if distance <= proximity_threshold {
                        overlaps.push(Overlap::Hunk {
                            path: a_file.path.clone(),
                            a_range,
                            b_range,
                            distance,
                        });
                    }
                }
            }
        }
    }

    overlaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_changeset(files: Vec<FileChange>) -> WorkspaceChangeset {
        WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc123".into(),
            changed_files: files,
            commits_ahead: 1,
            commits_behind: 0,
        }
    }

    fn make_file(path: &str, hunks: Vec<Hunk>) -> FileChange {
        FileChange {
            path: PathBuf::from(path),
            change_type: ChangeType::Modified,
            hunks,
            symbols_modified: vec![],
            exports_changed: vec![],
        }
    }

    #[test]
    fn file_overlap_detects_shared_files() {
        let a = make_changeset(vec![
            make_file("src/auth.ts", vec![]),
            make_file("src/payment.ts", vec![]),
        ]);
        let b = make_changeset(vec![
            make_file("src/payment.ts", vec![]),
            make_file("src/user.ts", vec![]),
        ]);

        let overlaps = compute_file_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::File { path, .. } => assert_eq!(path, &PathBuf::from("src/payment.ts")),
            _ => panic!("expected file overlap"),
        }
    }

    #[test]
    fn file_overlap_returns_empty_for_disjoint() {
        let a = make_changeset(vec![make_file("src/a.ts", vec![])]);
        let b = make_changeset(vec![make_file("src/b.ts", vec![])]);

        let overlaps = compute_file_overlaps(&a, &b);
        assert!(overlaps.is_empty());
    }

    #[test]
    fn hunk_overlap_detects_overlapping_ranges() {
        let a = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk { old_start: 10, old_lines: 10, new_start: 10, new_lines: 20 }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk { old_start: 20, old_lines: 10, new_start: 20, new_lines: 25 }],
        )]);

        let overlaps = compute_hunk_overlaps(&a, &b, 5);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Hunk { distance, .. } => assert_eq!(*distance, 0),
            _ => panic!("expected hunk overlap"),
        }
    }

    #[test]
    fn hunk_overlap_detects_nearby_ranges() {
        let a = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk { old_start: 10, old_lines: 5, new_start: 10, new_lines: 5 }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk { old_start: 18, old_lines: 5, new_start: 18, new_lines: 5 }],
        )]);

        // a_range: 10-14, b_range: 18-22, distance = 4 (within threshold of 5)
        let overlaps = compute_hunk_overlaps(&a, &b, 5);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Hunk { distance, .. } => assert_eq!(*distance, 4),
            _ => panic!("expected hunk overlap"),
        }
    }

    #[test]
    fn hunk_overlap_ignores_distant_ranges() {
        let a = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk { old_start: 10, old_lines: 5, new_start: 10, new_lines: 5 }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk { old_start: 200, old_lines: 5, new_start: 200, new_lines: 5 }],
        )]);

        let overlaps = compute_hunk_overlaps(&a, &b, 5);
        assert!(overlaps.is_empty());
    }
}
```

**Step 2: Update lib.rs**

```rust
// crates/grove-lib/src/lib.rs
pub mod diff;
pub mod fs;
pub mod types;

pub use types::*;
```

**Step 3: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add crates/grove-lib/src/diff.rs crates/grove-lib/src/lib.rs
git commit -m "feat: add file-level and hunk-level overlap detection"
```

---

### Task 5: Schema/config overlap detection

**Files:**
- Create: `crates/grove-lib/src/schema.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Write schema detection and overlap**

```rust
// crates/grove-lib/src/schema.rs
use crate::types::*;
use std::path::Path;

const DEFAULT_SCHEMA_PATTERNS: &[&str] = &[
    "*.sql",
    "package.json",
    "package-lock.json",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    ".env",
    "docker-compose.yml",
    "Dockerfile",
];

const MIGRATION_DIRS: &[&str] = &["migrations", "db/migrate", "prisma/migrations"];

pub fn classify_schema_file(path: &Path) -> Option<SchemaCategory> {
    let path_str = path.to_string_lossy();
    let filename = path.file_name()?.to_string_lossy();
    let ext = path.extension().map(|e| e.to_string_lossy().to_string());

    // Migrations
    for dir in MIGRATION_DIRS {
        if path_str.contains(dir) {
            return Some(SchemaCategory::Migration);
        }
    }
    if ext.as_deref() == Some("sql") {
        return Some(SchemaCategory::Migration);
    }

    // Package deps
    if matches!(
        filename.as_ref(),
        "package.json"
            | "package-lock.json"
            | "Cargo.toml"
            | "Cargo.lock"
            | "go.mod"
            | "go.sum"
            | "pnpm-lock.yaml"
            | "yarn.lock"
    ) {
        return Some(SchemaCategory::PackageDep);
    }

    // Env config
    if filename.starts_with(".env") {
        return Some(SchemaCategory::EnvConfig);
    }

    // CI
    if path_str.contains(".github/workflows")
        || path_str.contains(".gitlab-ci")
        || filename == "Jenkinsfile"
    {
        return Some(SchemaCategory::CI);
    }

    // Routes
    if path_str.contains("routes/") || path_str.contains("router") {
        return Some(SchemaCategory::Route);
    }

    None
}

pub fn compute_schema_overlaps(a: &WorkspaceChangeset, b: &WorkspaceChangeset) -> Vec<Overlap> {
    let mut overlaps = Vec::new();

    for a_file in &a.changed_files {
        if let Some(a_cat) = classify_schema_file(&a_file.path) {
            for b_file in &b.changed_files {
                if let Some(b_cat) = classify_schema_file(&b_file.path) {
                    if a_cat == b_cat {
                        overlaps.push(Overlap::Schema {
                            category: a_cat,
                            a_file: a_file.path.clone(),
                            b_file: b_file.path.clone(),
                            detail: format!(
                                "Both workspaces modify {:?} files",
                                a_cat
                            ),
                        });
                    }
                }
            }
        }
    }

    overlaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn classifies_migration_files() {
        assert_eq!(
            classify_schema_file(Path::new("migrations/001_init.sql")),
            Some(SchemaCategory::Migration)
        );
        assert_eq!(
            classify_schema_file(Path::new("db/migrate/20240101_users.sql")),
            Some(SchemaCategory::Migration)
        );
    }

    #[test]
    fn classifies_package_deps() {
        assert_eq!(
            classify_schema_file(Path::new("package.json")),
            Some(SchemaCategory::PackageDep)
        );
        assert_eq!(
            classify_schema_file(Path::new("Cargo.toml")),
            Some(SchemaCategory::PackageDep)
        );
    }

    #[test]
    fn classifies_env_config() {
        assert_eq!(
            classify_schema_file(Path::new(".env")),
            Some(SchemaCategory::EnvConfig)
        );
        assert_eq!(
            classify_schema_file(Path::new(".env.production")),
            Some(SchemaCategory::EnvConfig)
        );
    }

    #[test]
    fn classifies_ci() {
        assert_eq!(
            classify_schema_file(Path::new(".github/workflows/ci.yml")),
            Some(SchemaCategory::CI)
        );
    }

    #[test]
    fn returns_none_for_regular_files() {
        assert_eq!(classify_schema_file(Path::new("src/main.ts")), None);
        assert_eq!(classify_schema_file(Path::new("lib/utils.rs")), None);
    }

    #[test]
    fn schema_overlap_detects_same_category() {
        let a = WorkspaceChangeset {
            workspace_id: uuid::Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("package.json"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };
        let b = WorkspaceChangeset {
            workspace_id: uuid::Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("Cargo.toml"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_schema_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Schema { category, .. } => assert_eq!(*category, SchemaCategory::PackageDep),
            _ => panic!("expected schema overlap"),
        }
    }
}
```

**Step 2: Update lib.rs to include schema module**

Add `pub mod schema;` to `crates/grove-lib/src/lib.rs`.

**Step 3: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add crates/grove-lib/src/schema.rs crates/grove-lib/src/lib.rs
git commit -m "feat: add schema/config file classification and overlap detection"
```

---

## Phase 4: Orthogonality Scorer (Layers 1-3, 5)

### Task 6: Implement the scorer for file, hunk, symbol, and schema layers

**Files:**
- Create: `crates/grove-lib/src/scorer.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Write the scorer that runs all non-dependency layers**

```rust
// crates/grove-lib/src/scorer.rs
use crate::diff::{compute_file_overlaps, compute_hunk_overlaps};
use crate::schema::compute_schema_overlaps;
use crate::types::*;
use chrono::Utc;

const HUNK_PROXIMITY_THRESHOLD: u32 = 5;

/// Compute symbol overlaps by comparing symbols_modified in files touched by both.
pub fn compute_symbol_overlaps(a: &WorkspaceChangeset, b: &WorkspaceChangeset) -> Vec<Overlap> {
    let mut overlaps = Vec::new();

    for a_file in &a.changed_files {
        if let Some(b_file) = b.changed_files.iter().find(|f| f.path == a_file.path) {
            for a_sym in &a_file.symbols_modified {
                if let Some(b_sym) = b_file
                    .symbols_modified
                    .iter()
                    .find(|s| s.name == a_sym.name)
                {
                    overlaps.push(Overlap::Symbol {
                        path: a_file.path.clone(),
                        symbol_name: a_sym.name.clone(),
                        a_modification: format!(
                            "{:?} at lines {}-{}",
                            a_sym.kind, a_sym.range.start, a_sym.range.end
                        ),
                        b_modification: format!(
                            "{:?} at lines {}-{}",
                            b_sym.kind, b_sym.range.start, b_sym.range.end
                        ),
                    });
                }
            }
        }
    }

    overlaps
}

/// Run all analysis layers (except dependency, which requires the import graph).
/// Returns the pair analysis with all overlaps and the maximum score.
pub fn score_pair(
    a: &WorkspaceChangeset,
    b: &WorkspaceChangeset,
    dependency_overlaps: Vec<Overlap>,
) -> WorkspacePairAnalysis {
    let mut all_overlaps = Vec::new();

    // Layer 1: File overlap
    all_overlaps.extend(compute_file_overlaps(a, b));

    // Layer 2: Hunk overlap
    all_overlaps.extend(compute_hunk_overlaps(a, b, HUNK_PROXIMITY_THRESHOLD));

    // Layer 3: Symbol overlap
    all_overlaps.extend(compute_symbol_overlaps(a, b));

    // Layer 4: Schema/config overlap
    all_overlaps.extend(compute_schema_overlaps(a, b));

    // Layer 5: Dependency overlap (computed externally, passed in)
    all_overlaps.extend(dependency_overlaps);

    // Score = max severity across all overlaps
    let score = all_overlaps
        .iter()
        .map(|o| o.severity())
        .max()
        .unwrap_or(OrthogonalityScore::Green);

    // Merge order hint
    let merge_order_hint = if score == OrthogonalityScore::Black {
        MergeOrder::NeedsCoordination
    } else if a.changed_files.len() <= b.changed_files.len() {
        MergeOrder::AFirst
    } else {
        MergeOrder::BFirst
    };

    WorkspacePairAnalysis {
        workspace_a: a.workspace_id,
        workspace_b: b.workspace_id,
        score,
        overlaps: all_overlaps,
        merge_order_hint,
        last_computed: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_changeset_with_id(id: Uuid, files: Vec<FileChange>) -> WorkspaceChangeset {
        WorkspaceChangeset {
            workspace_id: id,
            merge_base: "abc123".into(),
            changed_files: files,
            commits_ahead: 1,
            commits_behind: 0,
        }
    }

    #[test]
    fn disjoint_workspaces_score_green() {
        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/auth.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk { old_start: 1, old_lines: 5, new_start: 1, new_lines: 5 }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/payment.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk { old_start: 1, old_lines: 5, new_start: 1, new_lines: 5 }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );

        let result = score_pair(&a, &b, vec![]);
        assert_eq!(result.score, OrthogonalityScore::Green);
        assert!(result.overlaps.is_empty());
    }

    #[test]
    fn overlapping_files_score_yellow() {
        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk { old_start: 1, old_lines: 5, new_start: 1, new_lines: 5 }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![
                    Hunk { old_start: 100, old_lines: 5, new_start: 100, new_lines: 5 },
                ],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );

        let result = score_pair(&a, &b, vec![]);
        assert_eq!(result.score, OrthogonalityScore::Yellow);
    }

    #[test]
    fn same_symbol_modified_scores_red() {
        let shared_symbol = Symbol {
            name: "processPayment".into(),
            kind: SymbolKind::Function,
            range: LineRange { start: 10, end: 30 },
            signature: Some("fn processPayment(amount: u64)".into()),
        };

        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/payment.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk { old_start: 10, old_lines: 20, new_start: 10, new_lines: 25 }],
                symbols_modified: vec![shared_symbol.clone()],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/payment.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk { old_start: 15, old_lines: 10, new_start: 15, new_lines: 12 }],
                symbols_modified: vec![Symbol {
                    name: "processPayment".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 15, end: 25 },
                    signature: Some("fn processPayment(amount: u64, token: &str)".into()),
                }],
                exports_changed: vec![],
            }],
        );

        let result = score_pair(&a, &b, vec![]);
        assert_eq!(result.score, OrthogonalityScore::Red);
    }

    #[test]
    fn dependency_overlap_scores_black() {
        let a = make_changeset_with_id(Uuid::new_v4(), vec![]);
        let b = make_changeset_with_id(Uuid::new_v4(), vec![]);

        let dep_overlaps = vec![Overlap::Dependency {
            changed_in: a.workspace_id,
            changed_file: PathBuf::from("src/auth.ts"),
            changed_export: ExportDelta::SignatureChanged {
                symbol_name: "authenticate".into(),
                old: Signature { text: "fn authenticate() -> bool".into() },
                new: Signature { text: "fn authenticate(token: &str) -> Result<bool>".into() },
            },
            affected_file: PathBuf::from("src/router.ts"),
            affected_usage: vec![Location {
                file: PathBuf::from("src/router.ts"),
                line: 47,
                column: 12,
            }],
        }];

        let result = score_pair(&a, &b, dep_overlaps);
        assert_eq!(result.score, OrthogonalityScore::Black);
    }

    #[test]
    fn score_is_max_across_all_layers() {
        // File overlap (Yellow) + Dependency overlap (Black) = Black
        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );

        let dep_overlaps = vec![Overlap::Dependency {
            changed_in: a.workspace_id,
            changed_file: PathBuf::from("src/auth.ts"),
            changed_export: ExportDelta::Added(Symbol {
                name: "newFn".into(),
                kind: SymbolKind::Function,
                range: LineRange { start: 1, end: 5 },
                signature: None,
            }),
            affected_file: PathBuf::from("src/other.ts"),
            affected_usage: vec![],
        }];

        let result = score_pair(&a, &b, dep_overlaps);
        assert_eq!(result.score, OrthogonalityScore::Black);
        // Should have overlaps from both file and dependency layers
        assert!(result.overlaps.len() >= 2);
    }
}
```

**Step 2: Update lib.rs**

Add `pub mod scorer;` to `crates/grove-lib/src/lib.rs`.

**Step 3: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add crates/grove-lib/src/scorer.rs crates/grove-lib/src/lib.rs
git commit -m "feat: add orthogonality scorer with file, hunk, symbol, and schema layers"
```

---

## Phase 5: Merge Order

### Task 7: Implement topological sort for merge sequencing

**Files:**
- Create: `crates/grove-lib/src/merge_order.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Write merge order computation**

```rust
// crates/grove-lib/src/merge_order.rs
use crate::types::*;
use petgraph::algo::toposort;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

/// Given pair analyses, compute the optimal merge sequence.
/// Returns workspace IDs in order (first to merge → last to merge),
/// plus any independent workspaces that can merge anytime.
pub fn compute_merge_order(
    analyses: &[WorkspacePairAnalysis],
    workspace_ids: &[WorkspaceId],
) -> MergeSequence {
    let mut graph = DiGraph::<WorkspaceId, ()>::new();
    let mut node_map: HashMap<WorkspaceId, NodeIndex> = HashMap::new();

    // Add all workspaces as nodes
    for id in workspace_ids {
        let idx = graph.add_node(*id);
        node_map.insert(*id, idx);
    }

    // Add edges based on pair analyses
    for analysis in analyses {
        if analysis.score == OrthogonalityScore::Green {
            continue; // No edge needed for independent pairs
        }

        let a_idx = node_map[&analysis.workspace_a];
        let b_idx = node_map[&analysis.workspace_b];

        match analysis.merge_order_hint {
            MergeOrder::AFirst => {
                graph.add_edge(a_idx, b_idx, ());
            }
            MergeOrder::BFirst => {
                graph.add_edge(b_idx, a_idx, ());
            }
            MergeOrder::NeedsCoordination => {
                // Black-level: add edge A->B (arbitrary but deterministic)
                graph.add_edge(a_idx, b_idx, ());
            }
            MergeOrder::Either => {} // No constraint
        }
    }

    // Topological sort
    match toposort(&graph, None) {
        Ok(sorted) => {
            let sequence: Vec<WorkspaceId> = sorted.iter().map(|idx| graph[*idx]).collect();

            // Identify independent workspaces (no edges at all)
            let independent: Vec<WorkspaceId> = workspace_ids
                .iter()
                .filter(|id| {
                    let idx = node_map[id];
                    graph.neighbors_undirected(idx).next().is_none()
                })
                .copied()
                .collect();

            let ordered: Vec<WorkspaceId> = sequence
                .into_iter()
                .filter(|id| !independent.contains(id))
                .collect();

            MergeSequence {
                ordered,
                independent,
                has_cycle: false,
            }
        }
        Err(_) => {
            // Cycle detected — fall back to ordering by fewest files changed
            MergeSequence {
                ordered: workspace_ids.to_vec(),
                independent: vec![],
                has_cycle: true,
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct MergeSequence {
    pub ordered: Vec<WorkspaceId>,
    pub independent: Vec<WorkspaceId>,
    pub has_cycle: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_analysis(
        a: WorkspaceId,
        b: WorkspaceId,
        score: OrthogonalityScore,
        hint: MergeOrder,
    ) -> WorkspacePairAnalysis {
        WorkspacePairAnalysis {
            workspace_a: a,
            workspace_b: b,
            score,
            overlaps: vec![],
            merge_order_hint: hint,
            last_computed: Utc::now(),
        }
    }

    #[test]
    fn all_green_means_all_independent() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Green, MergeOrder::Either),
            make_analysis(a, c, OrthogonalityScore::Green, MergeOrder::Either),
            make_analysis(b, c, OrthogonalityScore::Green, MergeOrder::Either),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c]);
        assert_eq!(result.independent.len(), 3);
        assert!(result.ordered.is_empty());
        assert!(!result.has_cycle);
    }

    #[test]
    fn a_first_hint_orders_correctly() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let analyses = vec![make_analysis(
            a,
            b,
            OrthogonalityScore::Red,
            MergeOrder::AFirst,
        )];

        let result = compute_merge_order(&analyses, &[a, b]);
        assert_eq!(result.ordered, vec![a, b]);
        assert!(!result.has_cycle);
    }

    #[test]
    fn three_workspace_chain() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();

        let analyses = vec![
            make_analysis(a, b, OrthogonalityScore::Yellow, MergeOrder::AFirst),
            make_analysis(b, c, OrthogonalityScore::Red, MergeOrder::BFirst),
        ];

        let result = compute_merge_order(&analyses, &[a, b, c]);
        // a before b, b before c
        let a_pos = result.ordered.iter().position(|x| *x == a).unwrap();
        let b_pos = result.ordered.iter().position(|x| *x == b).unwrap();
        let c_pos = result.ordered.iter().position(|x| *x == c).unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }
}
```

**Step 2: Update lib.rs**

Add `pub mod merge_order;` to `crates/grove-lib/src/lib.rs`.

**Step 3: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add crates/grove-lib/src/merge_order.rs crates/grove-lib/src/lib.rs
git commit -m "feat: add merge order computation with topological sort"
```

---

## Phase 6: Import Graph

### Task 8: Implement import graph data structure with overlay support

**Files:**
- Create: `crates/grove-lib/src/graph.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Write the import graph with base + overlay model**

```rust
// crates/grove-lib/src/graph.rs
use crate::types::*;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// The canonical import graph for the base branch.
#[derive(Debug, Clone, Default)]
pub struct ImportGraph {
    /// Forward edges: file -> [(imported_file, symbols)]
    pub imports: HashMap<PathBuf, Vec<(PathBuf, Vec<ImportedSymbol>)>>,
    /// Reverse edges: file -> [(importing_file, symbols)]
    pub dependents: HashMap<PathBuf, Vec<(PathBuf, Vec<ImportedSymbol>)>>,
    /// Exported symbols per file
    pub exports: HashMap<PathBuf, Vec<ExportedSymbol>>,
}

impl ImportGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resolved import relationship.
    pub fn add_import(
        &mut self,
        from_file: PathBuf,
        to_file: PathBuf,
        symbols: Vec<ImportedSymbol>,
    ) {
        self.imports
            .entry(from_file.clone())
            .or_default()
            .push((to_file.clone(), symbols.clone()));

        self.dependents
            .entry(to_file)
            .or_default()
            .push((from_file, symbols));
    }

    /// Set the exports for a file.
    pub fn set_exports(&mut self, file: PathBuf, exports: Vec<ExportedSymbol>) {
        self.exports.insert(file, exports);
    }

    /// Get all files that depend on the given file (direct dependents).
    pub fn get_dependents(&self, file: &PathBuf) -> Vec<&PathBuf> {
        self.dependents
            .get(file)
            .map(|deps| deps.iter().map(|(path, _)| path).collect())
            .unwrap_or_default()
    }

    /// Get all files that the given file imports from (direct dependencies).
    pub fn get_imports(&self, file: &PathBuf) -> Vec<&PathBuf> {
        self.imports
            .get(file)
            .map(|imports| imports.iter().map(|(path, _)| path).collect())
            .unwrap_or_default()
    }
}

/// Per-worktree overlay on the base graph.
#[derive(Debug, Clone, Default)]
pub struct GraphOverlay {
    pub modified_imports: HashMap<PathBuf, Vec<Import>>,
    pub modified_exports: HashMap<PathBuf, Vec<ExportedSymbol>>,
    pub added_files: HashMap<PathBuf, (Vec<Import>, Vec<ExportedSymbol>)>,
    pub removed_files: HashSet<PathBuf>,
}

impl GraphOverlay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a file's exports were modified in this overlay.
    pub fn has_export_changes(&self, file: &PathBuf) -> bool {
        self.modified_exports.contains_key(file) || self.added_files.contains_key(file)
    }

    /// Get the effective exports for a file, considering the overlay.
    pub fn effective_exports<'a>(
        &'a self,
        file: &PathBuf,
        base: &'a ImportGraph,
    ) -> Option<&'a Vec<ExportedSymbol>> {
        if self.removed_files.contains(file) {
            return None;
        }
        if let Some(exports) = self.modified_exports.get(file) {
            return Some(exports);
        }
        if let Some((_, exports)) = self.added_files.get(file) {
            return Some(exports);
        }
        base.exports.get(file)
    }
}

/// Compute dependency-level overlaps between two workspace overlays.
/// This is the most expensive layer: it traces export signature changes
/// through the import graph to find affected files in the other workspace.
pub fn compute_dependency_overlaps(
    a_changeset: &WorkspaceChangeset,
    b_changeset: &WorkspaceChangeset,
    a_overlay: &GraphOverlay,
    b_overlay: &GraphOverlay,
    base_graph: &ImportGraph,
) -> Vec<Overlap> {
    let mut overlaps = Vec::new();

    let b_changed_files: HashSet<&PathBuf> =
        b_changeset.changed_files.iter().map(|f| &f.path).collect();

    // For each file in A's changeset that has export changes...
    for a_file in &a_changeset.changed_files {
        for export_delta in &a_file.exports_changed {
            // Find all dependents of this file in the base graph
            let dependents = base_graph.get_dependents(&a_file.path);

            for dep_file in dependents {
                // If the dependent file is also changed in B's workspace,
                // that's a dependency-level conflict
                if b_changed_files.contains(dep_file) {
                    overlaps.push(Overlap::Dependency {
                        changed_in: a_changeset.workspace_id,
                        changed_file: a_file.path.clone(),
                        changed_export: export_delta.clone(),
                        affected_file: dep_file.clone(),
                        affected_usage: vec![], // Filled in by symbol-level analysis
                    });
                }
            }
        }
    }

    // Also check B's exports affecting A's files
    let a_changed_files: HashSet<&PathBuf> =
        a_changeset.changed_files.iter().map(|f| &f.path).collect();

    for b_file in &b_changeset.changed_files {
        for export_delta in &b_file.exports_changed {
            let dependents = base_graph.get_dependents(&b_file.path);

            for dep_file in dependents {
                if a_changed_files.contains(dep_file) {
                    overlaps.push(Overlap::Dependency {
                        changed_in: b_changeset.workspace_id,
                        changed_file: b_file.path.clone(),
                        changed_export: export_delta.clone(),
                        affected_file: dep_file.clone(),
                        affected_usage: vec![],
                    });
                }
            }
        }
    }

    overlaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn import_graph_tracks_relationships() {
        let mut graph = ImportGraph::new();
        graph.add_import(
            PathBuf::from("src/router.ts"),
            PathBuf::from("src/auth.ts"),
            vec![ImportedSymbol { name: "authenticate".into(), alias: None }],
        );

        assert_eq!(
            graph.get_dependents(&PathBuf::from("src/auth.ts")),
            vec![&PathBuf::from("src/router.ts")]
        );
        assert_eq!(
            graph.get_imports(&PathBuf::from("src/router.ts")),
            vec![&PathBuf::from("src/auth.ts")]
        );
    }

    #[test]
    fn dependency_overlap_detects_cross_workspace_break() {
        let mut base_graph = ImportGraph::new();
        // router.ts imports from auth.ts
        base_graph.add_import(
            PathBuf::from("src/router.ts"),
            PathBuf::from("src/auth.ts"),
            vec![ImportedSymbol { name: "authenticate".into(), alias: None }],
        );

        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();

        // Workspace A changes auth.ts (modifies authenticate signature)
        let a = WorkspaceChangeset {
            workspace_id: a_id,
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("src/auth.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![ExportDelta::SignatureChanged {
                    symbol_name: "authenticate".into(),
                    old: Signature { text: "fn authenticate() -> bool".into() },
                    new: Signature {
                        text: "fn authenticate(token: &str) -> Result<bool>".into(),
                    },
                }],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        // Workspace B changes router.ts (which depends on auth.ts)
        let b = WorkspaceChangeset {
            workspace_id: b_id,
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("src/router.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let a_overlay = GraphOverlay::new();
        let b_overlay = GraphOverlay::new();

        let overlaps =
            compute_dependency_overlaps(&a, &b, &a_overlay, &b_overlay, &base_graph);

        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Dependency {
                changed_in,
                changed_file,
                affected_file,
                ..
            } => {
                assert_eq!(*changed_in, a_id);
                assert_eq!(changed_file, &PathBuf::from("src/auth.ts"));
                assert_eq!(affected_file, &PathBuf::from("src/router.ts"));
            }
            _ => panic!("expected dependency overlap"),
        }
    }

    #[test]
    fn no_dependency_overlap_when_no_exports_changed() {
        let mut base_graph = ImportGraph::new();
        base_graph.add_import(
            PathBuf::from("src/router.ts"),
            PathBuf::from("src/auth.ts"),
            vec![ImportedSymbol { name: "authenticate".into(), alias: None }],
        );

        let a = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("src/auth.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![], // No export changes!
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let b = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("src/router.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_dependency_overlaps(
            &a,
            &b,
            &GraphOverlay::new(),
            &GraphOverlay::new(),
            &base_graph,
        );

        assert!(overlaps.is_empty());
    }
}
```

**Step 2: Update lib.rs**

Add `pub mod graph;` to `crates/grove-lib/src/lib.rs`.

**Step 3: Run tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass.

**Step 4: Commit**

```bash
git add crates/grove-lib/src/graph.rs crates/grove-lib/src/lib.rs
git commit -m "feat: add import graph with base+overlay model and dependency overlap detection"
```

---

## Phase 7: Tree-sitter Integration

### Task 9: Set up tree-sitter parsing and LanguageAnalyzer trait

**Files:**
- Create: `crates/grove-lib/src/languages/mod.rs`
- Create: `crates/grove-lib/src/languages/typescript.rs`
- Create: `crates/grove-lib/src/languages/rust_lang.rs`
- Create: `crates/grove-lib/src/treesitter.rs`
- Modify: `crates/grove-lib/src/lib.rs`

**Step 1: Define the LanguageAnalyzer trait**

```rust
// crates/grove-lib/src/languages/mod.rs
pub mod rust_lang;
pub mod typescript;

use crate::types::*;
use std::path::Path;

/// Trait for language-specific symbol and import extraction.
/// Each language implements this to provide tree-sitter-based analysis.
pub trait LanguageAnalyzer: Send + Sync {
    fn language_id(&self) -> &str;
    fn file_extensions(&self) -> &[&str];
    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError>;
    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError>;
    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError>;
    fn is_schema_file(&self, path: &Path) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),
}

/// Registry of language analyzers. Matches file extensions to analyzers.
pub struct LanguageRegistry {
    analyzers: Vec<Box<dyn LanguageAnalyzer>>,
}

impl LanguageRegistry {
    pub fn new() -> Self {
        Self { analyzers: vec![] }
    }

    /// Create a registry with the built-in analyzers (TypeScript, Rust).
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(typescript::TypeScriptAnalyzer::new()));
        registry.register(Box::new(rust_lang::RustAnalyzer::new()));
        registry
    }

    pub fn register(&mut self, analyzer: Box<dyn LanguageAnalyzer>) {
        self.analyzers.push(analyzer);
    }

    pub fn analyzer_for_file(&self, path: &Path) -> Option<&dyn LanguageAnalyzer> {
        let ext = path.extension()?.to_str()?;
        self.analyzers
            .iter()
            .find(|a| a.file_extensions().contains(&ext))
            .map(|a| a.as_ref())
    }
}
```

**Step 2: Implement TypeScript analyzer (symbol and import extraction)**

This is the largest single piece of code in the project. The TypeScript analyzer uses tree-sitter to parse TS/JS files and extract:
- Functions, classes, interfaces, type aliases, enums, constants
- Import statements with their symbols
- Export declarations

```rust
// crates/grove-lib/src/languages/typescript.rs
use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::{Parser, Query, QueryCursor};

pub struct TypeScriptAnalyzer {
    parser_ts: std::sync::Mutex<Parser>,
    parser_tsx: std::sync::Mutex<Parser>,
}

impl TypeScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser_ts = Parser::new();
        parser_ts
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to set typescript language");

        let mut parser_tsx = Parser::new();
        parser_tsx
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .expect("failed to set tsx language");

        Self {
            parser_ts: std::sync::Mutex::new(parser_ts),
            parser_tsx: std::sync::Mutex::new(parser_tsx),
        }
    }

    fn parse(&self, source: &[u8], is_tsx: bool) -> Result<tree_sitter::Tree, AnalysisError> {
        let mut parser = if is_tsx {
            self.parser_tsx.lock().unwrap()
        } else {
            self.parser_ts.lock().unwrap()
        };
        parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("tree-sitter parse failed".into()))
    }
}

impl LanguageAnalyzer for TypeScriptAnalyzer {
    fn language_id(&self) -> &str {
        "typescript"
    }

    fn file_extensions(&self) -> &[&str] {
        &["ts", "tsx", "js", "jsx", "mts", "mjs"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            match child.kind() {
                "function_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Function,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: Some(
                                get_first_line(source, child.start_byte(), child.end_byte()),
                            ),
                        });
                    }
                }
                "class_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Class,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "interface_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Interface,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "type_alias_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::TypeAlias,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "enum_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Enum,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    // const/let/var declarations
                    let mut decl_cursor = child.walk();
                    for decl_child in child.children(&mut decl_cursor) {
                        if decl_child.kind() == "variable_declarator" {
                            if let Some(name_node) = decl_child.child_by_field_name("name") {
                                let name =
                                    name_node.utf8_text(source).unwrap_or("").to_string();
                                symbols.push(Symbol {
                                    name,
                                    kind: SymbolKind::Variable,
                                    range: LineRange {
                                        start: child.start_position().row as u32 + 1,
                                        end: child.end_position().row as u32 + 1,
                                    },
                                    signature: None,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "import_statement" {
                let line = child.start_position().row as u32 + 1;
                let mut source_path = String::new();
                let mut symbols = Vec::new();

                let mut import_cursor = child.walk();
                for import_child in child.children(&mut import_cursor) {
                    match import_child.kind() {
                        "string" | "template_string" => {
                            let raw = import_child.utf8_text(source).unwrap_or("");
                            // Strip quotes
                            source_path = raw.trim_matches(|c| c == '\'' || c == '"').to_string();
                        }
                        "import_clause" => {
                            let mut clause_cursor = import_child.walk();
                            for clause_child in import_child.children(&mut clause_cursor) {
                                if clause_child.kind() == "named_imports" {
                                    let mut named_cursor = clause_child.walk();
                                    for named_child in clause_child.children(&mut named_cursor) {
                                        if named_child.kind() == "import_specifier" {
                                            let name = named_child
                                                .child_by_field_name("name")
                                                .map(|n| {
                                                    n.utf8_text(source)
                                                        .unwrap_or("")
                                                        .to_string()
                                                })
                                                .unwrap_or_default();
                                            let alias = named_child
                                                .child_by_field_name("alias")
                                                .map(|n| {
                                                    n.utf8_text(source)
                                                        .unwrap_or("")
                                                        .to_string()
                                                });
                                            if !name.is_empty() {
                                                symbols.push(ImportedSymbol { name, alias });
                                            }
                                        }
                                    }
                                }
                                if clause_child.kind() == "identifier" {
                                    // Default import
                                    let name = clause_child
                                        .utf8_text(source)
                                        .unwrap_or("")
                                        .to_string();
                                    if !name.is_empty() {
                                        symbols.push(ImportedSymbol {
                                            name: "default".to_string(),
                                            alias: Some(name),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if !source_path.is_empty() {
                    imports.push(Import {
                        source: source_path,
                        symbols,
                        line,
                    });
                }
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "export_statement" {
                let mut export_cursor = child.walk();
                for export_child in child.children(&mut export_cursor) {
                    match export_child.kind() {
                        "function_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::Function,
                                    signature: Some(get_first_line(
                                        source,
                                        export_child.start_byte(),
                                        export_child.end_byte(),
                                    )),
                                });
                            }
                        }
                        "class_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::Class,
                                    signature: None,
                                });
                            }
                        }
                        "interface_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::Interface,
                                    signature: None,
                                });
                            }
                        }
                        "type_alias_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::TypeAlias,
                                    signature: None,
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(exports)
    }

    fn is_schema_file(&self, path: &Path) -> bool {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        matches!(
            filename.as_str(),
            "package.json" | "tsconfig.json" | "next.config.js" | "next.config.ts"
                | "vite.config.ts" | "webpack.config.js"
        )
    }
}

fn get_first_line(source: &[u8], start: usize, end: usize) -> String {
    let slice = &source[start..end.min(source.len())];
    let text = String::from_utf8_lossy(slice);
    text.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_function_symbols() {
        let source = br#"
function processPayment(amount: number): boolean {
    return true;
}

function validateUser(id: string): User {
    return {} as User;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "processPayment");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert_eq!(symbols[1].name, "validateUser");
    }

    #[test]
    fn extracts_class_and_interface() {
        let source = br#"
class PaymentService {
    process() {}
}

interface PaymentConfig {
    amount: number;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "PaymentService");
        assert_eq!(symbols[0].kind, SymbolKind::Class);
        assert_eq!(symbols[1].name, "PaymentConfig");
        assert_eq!(symbols[1].kind, SymbolKind::Interface);
    }

    #[test]
    fn extracts_named_imports() {
        let source = br#"
import { processPayment, PaymentConfig } from './payment';
import { validateUser } from '../auth';
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "./payment");
        assert_eq!(imports[0].symbols.len(), 2);
        assert_eq!(imports[0].symbols[0].name, "processPayment");
        assert_eq!(imports[0].symbols[1].name, "PaymentConfig");
        assert_eq!(imports[1].source, "../auth");
    }

    #[test]
    fn extracts_exported_functions() {
        let source = br#"
export function processPayment(amount: number): boolean {
    return true;
}

export interface PaymentResult {
    success: boolean;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "processPayment");
        assert_eq!(exports[0].kind, SymbolKind::Function);
        assert_eq!(exports[1].name, "PaymentResult");
        assert_eq!(exports[1].kind, SymbolKind::Interface);
    }
}
```

**Step 3: Implement Rust analyzer (stub — full implementation is a follow-up)**

```rust
// crates/grove-lib/src/languages/rust_lang.rs
use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

pub struct RustAnalyzer {
    parser: std::sync::Mutex<Parser>,
}

impl RustAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("failed to set rust language");
        Self {
            parser: std::sync::Mutex::new(parser),
        }
    }
}

impl LanguageAnalyzer for RustAnalyzer {
    fn language_id(&self) -> &str {
        "rust"
    }

    fn file_extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            match child.kind() {
                "function_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Function,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: Some(get_signature_line(source, child.start_byte())),
                        });
                    }
                }
                "struct_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Struct,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "enum_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Enum,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "trait_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Trait,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "impl_item" => {
                    if let Some(name_node) = child.child_by_field_name("type") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Impl,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "use_declaration" {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                let line = child.start_position().row as u32 + 1;
                // Extract the module path from "use crate::module::symbol;"
                let path = text
                    .trim_start_matches("use ")
                    .trim_end_matches(';')
                    .to_string();
                imports.push(Import {
                    source: path,
                    symbols: vec![], // TODO: parse use tree for individual symbols
                    line,
                });
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        // In Rust, "pub" items are exports. Check for pub visibility.
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            // Check if the item has a visibility_modifier child with "pub"
            let is_pub = child
                .children(&mut child.walk())
                .any(|c| c.kind() == "visibility_modifier");

            if is_pub {
                match child.kind() {
                    "function_item" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            exports.push(ExportedSymbol {
                                name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                kind: SymbolKind::Function,
                                signature: Some(get_signature_line(source, child.start_byte())),
                            });
                        }
                    }
                    "struct_item" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            exports.push(ExportedSymbol {
                                name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                kind: SymbolKind::Struct,
                                signature: None,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(exports)
    }

    fn is_schema_file(&self, path: &Path) -> bool {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        matches!(filename.as_str(), "Cargo.toml" | "build.rs")
    }
}

fn get_signature_line(source: &[u8], start: usize) -> String {
    let slice = &source[start..];
    let text = String::from_utf8_lossy(slice);
    text.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_rust_function_symbols() {
        let source = br#"
fn process_payment(amount: u64) -> bool {
    true
}

pub fn validate_user(id: &str) -> User {
    todo!()
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "process_payment");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert_eq!(symbols[1].name, "validate_user");
    }

    #[test]
    fn extracts_rust_pub_exports() {
        let source = br#"
pub fn exported_fn() {}

fn private_fn() {}

pub struct ExportedStruct {
    pub field: i32,
}
"#;
        let analyzer = RustAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "exported_fn");
        assert_eq!(exports[1].name, "ExportedStruct");
    }

    #[test]
    fn extracts_rust_use_imports() {
        let source = br#"
use crate::types::Workspace;
use std::collections::HashMap;
"#;
        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 2);
        assert!(imports[0].source.contains("crate::types::Workspace"));
        assert!(imports[1].source.contains("std::collections::HashMap"));
    }
}
```

**Step 4: Create treesitter.rs (optional helper, can be a simple re-export for now)**

```rust
// crates/grove-lib/src/treesitter.rs
//! Tree-sitter utilities. Currently language-specific parsing is handled
//! directly in each LanguageAnalyzer. This module provides shared helpers.

pub use tree_sitter::{Parser, Tree};
```

**Step 5: Update lib.rs**

```rust
// crates/grove-lib/src/lib.rs
pub mod diff;
pub mod fs;
pub mod graph;
pub mod languages;
pub mod merge_order;
pub mod schema;
pub mod scorer;
pub mod treesitter;
pub mod types;

pub use types::*;
```

**Step 6: Build and run all tests**

Run: `cargo test -p grove-lib`
Expected: All tests pass. Tree-sitter C compilation may take a moment on first build.

**Step 7: Commit**

```bash
git add crates/grove-lib/src/languages/ crates/grove-lib/src/treesitter.rs crates/grove-lib/src/lib.rs
git commit -m "feat: add LanguageAnalyzer trait with TypeScript and Rust analyzers"
```

---

## Phase 8: SQLite Persistence

### Task 10: Implement database schema and read/write operations

**Files:**
- Create: `crates/grove-daemon/src/db.rs`
- Modify: `crates/grove-daemon/src/lib.rs`

**Step 1: Write the database layer**

Implement SQLite schema creation, workspace CRUD, and pair analysis persistence. Use `rusqlite` with bundled SQLite. All reads/writes go through this module — the daemon state actor delegates persistence here.

Reference the SQLite schema from design doc section 2.

Key operations:
- `Database::open(path)` — open or create database, run migrations
- `Database::save_workspace(workspace)` / `load_workspaces()`
- `Database::save_pair_analysis(analysis)` / `load_pair_analyses()`
- `Database::save_base_graph_entry(path, imports, exports, hash, commit)` / `load_base_graph()`
- `Database::save_workspace_delta(workspace_id, file_path, delta)` / `load_workspace_deltas(workspace_id)`

Write tests using an in-memory SQLite database (`:memory:` connection string).

**Step 2: Run tests**

Run: `cargo test -p grove-daemon`

**Step 3: Commit**

```bash
git add crates/grove-daemon/src/db.rs crates/grove-daemon/src/lib.rs
git commit -m "feat: add SQLite persistence layer for workspaces, analyses, and import graph"
```

---

## Phase 9: Daemon Core

### Task 11: Implement the state actor

**Files:**
- Create: `crates/grove-daemon/src/state.rs`

Implement `DaemonState` struct and the actor message loop. The state actor owns all mutable data and processes `StateMessage` variants sequentially via `tokio::mpsc::Receiver`. Socket handlers and filesystem watchers send messages via the corresponding `Sender`.

Key messages: `FileChanged`, `AnalysisComplete`, `Query` (with `oneshot::Sender` for response), `BaseRefChanged`, `WorktreeReindexComplete`.

Reference design doc section 4 (Concurrency Model).

**Step 1-4: Implement, test with mock messages, commit.**

### Task 12: Implement filesystem watcher with debouncer and circuit breaker

**Files:**
- Create: `crates/grove-daemon/src/watcher.rs`

Use `notify` crate for filesystem events. Implement:
- Debounce window (configurable, default 500ms)
- Per-worktree `.gitignore` filtering via `ignore` crate
- Circuit breaker: >100 files per worktree per debounce window triggers full re-index
- Git ref watching (`.git/refs/remotes/`) for base branch changes
- Hash comparison on FETCH_HEAD changes (only rebuild if base_commit actually moved)

**Step 1-4: Implement, test with temp directories, commit.**

### Task 13: Implement Unix socket server

**Files:**
- Create: `crates/grove-daemon/src/socket.rs`

NDJSON protocol over `tokio::net::UnixListener`. Use `tokio-util`'s `LinesCodec` with `Framed<UnixStream, LinesCodec>`. Parse incoming JSON requests, send to state actor via channel, return JSON response.

Support `subscribe` method for persistent connections (server-sent events).

**Step 1-4: Implement, test with mock socket connections, commit.**

### Task 14: Implement daemon lifecycle

**Files:**
- Create: `crates/grove-daemon/src/lifecycle.rs`

PID file management (`.grove/daemon.pid`), graceful shutdown on SIGTERM, cleanup of socket file on exit.

**Step 1-4: Implement, test, commit.**

### Task 15: Wire up daemon lib.rs

**Files:**
- Modify: `crates/grove-daemon/src/lib.rs`

Export `pub async fn run(config: GroveConfig)` that:
1. Initializes tracing
2. Opens SQLite database
3. Starts state actor
4. Starts filesystem watcher
5. Starts socket server
6. Runs until shutdown signal

**Step 1-4: Implement, integration test with temp git repo, commit.**

---

## Phase 10: CLI

### Task 16: Implement socket client

**Files:**
- Create: `crates/grove-cli/src/client.rs`

Connect to daemon's Unix socket at `.grove/daemon.sock`. Send NDJSON request, read NDJSON response. Auto-start daemon if socket doesn't exist (spawn `grove daemon start` as child process, poll until socket appears).

Use `tokio-util`'s `LinesCodec` on the client side too.

**Step 1-4: Implement, test, commit.**

### Task 17: Implement CLI commands

**Files:**
- Create: `crates/grove-cli/src/commands/status.rs`
- Create: `crates/grove-cli/src/commands/create.rs`
- Create: `crates/grove-cli/src/commands/conflicts.rs`
- Create: `crates/grove-cli/src/commands/list.rs`
- Create: `crates/grove-cli/src/commands/retire.rs`
- Create: `crates/grove-cli/src/commands/rebase.rs`
- Create: `crates/grove-cli/src/commands/merge_order.rs`
- Create: `crates/grove-cli/src/commands/daemon.rs`
- Create: `crates/grove-cli/src/commands/config.rs`
- Create: `crates/grove-cli/src/commands/init.rs`
- Create: `crates/grove-cli/src/commands/switch.rs`
- Create: `crates/grove-cli/src/commands/mod.rs`
- Create: `crates/grove-cli/src/render.rs`

Each command:
1. Parses args via clap
2. Sends request to daemon via socket client
3. Receives response
4. Renders output (colored terminal or `--json`)

Start with `status`, `conflicts`, and `list` as they're the most used. Reference design doc section 3 for exact output format.

`init` command is special — it generates shell function text for zsh/bash/fish. No daemon communication needed.

**Step 1: Implement status command with snapshot test for output format.**
**Step 2: Implement conflicts command.**
**Step 3: Implement remaining commands one at a time.**
**Step 4: Commit after each command.**

### Task 18: Wire up CLI lib.rs

**Files:**
- Modify: `crates/grove-cli/src/lib.rs`

Use clap derive macros for the command tree. Export `pub async fn run(args: CliArgs)` that dispatches to command handlers.

```rust
#[derive(clap::Parser)]
#[command(name = "grove", about = "Git worktree workspace manager with conflict intelligence")]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(clap::Subcommand)]
pub enum Commands {
    Status,
    Create { name: String, #[arg(long)] branch: Option<String>, #[arg(long)] from: Option<String>, #[arg(long)] issue: Option<String> },
    Switch { name: String, #[arg(long)] print_path: bool },
    List { #[arg(long)] stale: bool },
    Conflicts { a: Option<String>, b: Option<String>, #[arg(long)] preview: Option<String> },
    Retire { name: Option<String>, #[arg(long)] auto: bool },
    Rebase { name: Option<String>, #[arg(long)] sequence: bool, #[arg(long, rename_all = "kebab")] r#continue: bool },
    MergeOrder { #[arg(long)] explain: bool },
    Daemon { #[command(subcommand)] action: DaemonAction },
    Config { #[command(subcommand)] action: Option<ConfigAction> },
    Init { shell: String },
}
```

**Step 1-4: Implement, test, commit.**

---

## Phase 11: Single Binary Entry Point

### Task 19: Implement the root main.rs with fork-safe daemon start

**Files:**
- Modify: `crates/grove/src/main.rs`

This is the multiplexed entry point. Key requirement: daemonization occurs synchronously BEFORE tokio runtime construction to avoid the fork deadlock (see design doc section 4).

```rust
// crates/grove/src/main.rs
use clap::Parser;

fn main() {
    let args = grove_cli::CliArgs::parse();

    match &args.command {
        Some(grove_cli::Commands::Daemon { action }) => match action {
            grove_cli::DaemonAction::Start => {
                // 1. Daemonize synchronously, BEFORE tokio
                // (double-fork, setsid, redirect I/O)
                daemonize::Daemonize::new()
                    .pid_file(".grove/daemon.pid")
                    .working_directory(".")
                    .start()
                    .expect("failed to daemonize");

                // 2. Build tokio runtime in detached child only
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(grove_daemon::run());
            }
            _ => {
                // Stop/status: lightweight, can use tokio normally
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(grove_cli::run());
            }
        },
        _ => {
            // All CLI commands
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(grove_cli::run());
        }
    }
}
```

**Step 1: Implement main.rs with the fork-safe pattern.**
**Step 2: Build full binary.**

Run: `cargo build -p grove`
Expected: Single `grove` binary in `target/debug/grove`.

**Step 3: Smoke test.**

Run: `./target/debug/grove --help`
Expected: Shows usage with all subcommands.

**Step 4: Commit.**

```bash
git add crates/grove/src/main.rs
git commit -m "feat: implement multiplexed binary entry point with fork-safe daemonization"
```

---

## Phase 12: Shell Integration

### Task 20: Implement grove init for zsh/bash/fish

The `init` command outputs shell function text. No daemon needed.

**Files:**
- `crates/grove-cli/src/commands/init.rs` (already created in Task 17)

Shell functions to generate:
- **zsh/bash:** `gr()` function that intercepts `switch` to `cd`, passes everything else through
- **fish:** `function gr` with equivalent logic

Reference design doc section 3 (Shell Integration) for exact function definitions.

**Step 1: Write init command with shell detection.**
**Step 2: Snapshot test for each shell's output.**
**Step 3: Commit.**

---

## Phase 13: Integration Tests

### Task 21: End-to-end test with real git repo

**Files:**
- Create: `tests/integration/smoke_test.rs`

Create a temporary git repo programmatically using `gix`. Add files, create branches, create worktrees. Start the daemon in-process (skip daemonization for testing). Verify:
1. `grove status` returns correct workspace list
2. Two workspaces modifying the same file produce a Yellow or Red score
3. `grove conflicts <a> <b>` returns detailed overlap information
4. `grove retire` cleans up a merged workspace

**Step 1: Write the test setup helper that creates a git repo with worktrees.**
**Step 2: Write the smoke test.**
**Step 3: Run tests.**

Run: `cargo test --test smoke_test`
Expected: All tests pass.

**Step 4: Commit.**

```bash
git add tests/
git commit -m "test: add end-to-end integration test with real git repos"
```

---

## Phase 14: CI/CD

### Task 22: GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`

Matrix build: `ubuntu-latest`, `macos-latest`, `windows-latest` with stable Rust. Steps: checkout, cache cargo, `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`.

**Step 1: Write CI workflow.**
**Step 2: Commit.**

```bash
git add .github/
git commit -m "ci: add GitHub Actions workflow for build, test, and clippy"
```

### Task 23: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`

Triggered on tag push (`v*`). Builds release binaries for `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`, `x86_64-windows`. Uploads to GitHub Releases. Uses `cross` for cross-compilation.

**Step 1: Write release workflow.**
**Step 2: Commit.**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow for cross-platform binary distribution"
```

---

## Summary

| Phase | Tasks | What it delivers |
|-------|-------|-----------------|
| 1 | 1 | Cargo workspace, 4 crates, compiles |
| 2 | 2-3 | Core types, FileSystem trait |
| 3 | 4-5 | File/hunk/schema overlap detection |
| 4 | 6 | Orthogonality scorer (layers 1-3, 5) |
| 5 | 7 | Merge order computation |
| 6 | 8 | Import graph with overlay model |
| 7 | 9 | Tree-sitter integration, TS + Rust analyzers |
| 8 | 10 | SQLite persistence |
| 9 | 11-15 | Daemon (actor, watcher, socket, lifecycle) |
| 10 | 16-18 | CLI (client, commands, rendering) |
| 11 | 19 | Single binary entry point |
| 12 | 20 | Shell integration (grove init) |
| 13 | 21 | Integration tests |
| 14 | 22-23 | CI/CD |

**After Phase 7, you have a fully testable analysis engine.** Everything from Phase 8 onward is plumbing (persistence, networking, CLI rendering) around the core library.

**Critical path:** Phases 1-7 must be sequential (each builds on the previous). Phases 8-12 can be partially parallelized (daemon and CLI can be built concurrently once the lib is stable).
