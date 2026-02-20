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
