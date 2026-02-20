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
    use chrono::TimeZone;
    use serde_json::json;
    use uuid::Uuid;

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

    #[test]
    fn line_range_overlaps_is_commutative_for_edge_cases() {
        let cases = vec![
            (
                LineRange { start: 0, end: 0 },
                LineRange { start: 0, end: 0 },
            ),
            (
                LineRange {
                    start: 0,
                    end: u32::MAX,
                },
                LineRange {
                    start: u32::MAX,
                    end: u32::MAX,
                },
            ),
            (
                LineRange { start: 10, end: 10 },
                LineRange { start: 11, end: 11 },
            ),
        ];

        for (a, b) in cases {
            assert_eq!(a.overlaps(&b), b.overlaps(&a));
        }
    }

    #[test]
    fn line_range_distance_is_commutative_for_edge_cases() {
        let cases = vec![
            (
                LineRange { start: 0, end: 0 },
                LineRange { start: 1, end: 1 },
            ),
            (
                LineRange { start: 5, end: 15 },
                LineRange { start: 20, end: 30 },
            ),
            (
                LineRange {
                    start: u32::MAX,
                    end: u32::MAX,
                },
                LineRange {
                    start: u32::MAX,
                    end: u32::MAX,
                },
            ),
        ];

        for (a, b) in cases {
            assert_eq!(a.distance(&b), b.distance(&a));
        }
    }

    #[test]
    fn dependency_overlap_is_black_and_preserves_unicode_names() {
        let overlap = Overlap::Dependency {
            changed_in: Uuid::new_v4(),
            changed_file: PathBuf::from("src/深い/space name.rs"),
            changed_export: ExportDelta::SignatureChanged {
                symbol_name: "föö_λ".to_string(),
                old: Signature {
                    text: "fn föö_λ()".to_string(),
                },
                new: Signature {
                    text: "fn föö_λ(x: i32)".to_string(),
                },
            },
            affected_file: PathBuf::from("src/consumer.rs"),
            affected_usage: vec![],
        };

        assert_eq!(overlap.severity(), OrthogonalityScore::Black);
    }

    #[test]
    fn line_range_grid_invariants_hold_for_many_cases() {
        let mut ranges = Vec::new();
        for start in 0..80 {
            for width in 0..6 {
                ranges.push(LineRange {
                    start,
                    end: start + width,
                });
            }
        }
        ranges.push(LineRange {
            start: u32::MAX - 10,
            end: u32::MAX - 5,
        });
        ranges.push(LineRange {
            start: u32::MAX - 1,
            end: u32::MAX,
        });

        for a in &ranges {
            for b in &ranges {
                let overlaps_ab = a.overlaps(b);
                let overlaps_ba = b.overlaps(a);
                assert_eq!(overlaps_ab, overlaps_ba);

                let dist_ab = a.distance(b);
                let dist_ba = b.distance(a);
                assert_eq!(dist_ab, dist_ba);

                if overlaps_ab {
                    assert_eq!(dist_ab, 0);
                } else {
                    assert!(dist_ab > 0);
                }
            }
        }
    }

    #[test]
    fn line_range_distance_handles_extreme_non_overlapping_values() {
        let low = LineRange { start: 0, end: 0 };
        let high = LineRange {
            start: u32::MAX - 5,
            end: u32::MAX,
        };

        assert_eq!(low.distance(&high), u32::MAX - 5);
        assert_eq!(high.distance(&low), u32::MAX - 5);
        assert!(!low.overlaps(&high));
    }

    #[test]
    fn adjacent_ranges_have_unit_distance() {
        let a = LineRange { start: 10, end: 20 };
        let b = LineRange { start: 21, end: 40 };
        assert_eq!(a.distance(&b), 1);
        assert_eq!(b.distance(&a), 1);
    }

    #[test]
    fn overlap_severity_exhaustive_mapping() {
        let symbol = Symbol {
            name: "f".into(),
            kind: SymbolKind::Function,
            range: LineRange { start: 1, end: 1 },
            signature: None,
        };

        let cases = vec![
            (
                Overlap::File {
                    path: PathBuf::from("f"),
                    a_change: ChangeType::Added,
                    b_change: ChangeType::Deleted,
                },
                OrthogonalityScore::Yellow,
            ),
            (
                Overlap::Hunk {
                    path: PathBuf::from("f"),
                    a_range: LineRange { start: 1, end: 1 },
                    b_range: LineRange { start: 10, end: 10 },
                    distance: 9,
                },
                OrthogonalityScore::Yellow,
            ),
            (
                Overlap::Hunk {
                    path: PathBuf::from("f"),
                    a_range: LineRange { start: 1, end: 1 },
                    b_range: LineRange { start: 1, end: 1 },
                    distance: 0,
                },
                OrthogonalityScore::Red,
            ),
            (
                Overlap::Symbol {
                    path: PathBuf::from("f"),
                    symbol_name: "f".into(),
                    a_modification: "a".into(),
                    b_modification: "b".into(),
                },
                OrthogonalityScore::Red,
            ),
            (
                Overlap::Dependency {
                    changed_in: Uuid::new_v4(),
                    changed_file: PathBuf::from("a"),
                    changed_export: ExportDelta::Added(symbol.clone()),
                    affected_file: PathBuf::from("b"),
                    affected_usage: vec![],
                },
                OrthogonalityScore::Black,
            ),
            (
                Overlap::Schema {
                    category: SchemaCategory::EnvConfig,
                    a_file: PathBuf::from(".env"),
                    b_file: PathBuf::from(".env.local"),
                    detail: "d".into(),
                },
                OrthogonalityScore::Yellow,
            ),
        ];

        for (overlap, expected) in cases {
            assert_eq!(overlap.severity(), expected);
        }
    }

    #[test]
    fn change_type_deserialization_rejects_unknown_variant() {
        let err = serde_json::from_str::<ChangeType>("\"Moved\"").unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn workspace_metadata_default_serializes_optional_fields_as_null() {
        let metadata = WorkspaceMetadata::default();
        let value = serde_json::to_value(metadata).unwrap();

        assert_eq!(value.get("description"), Some(&serde_json::Value::Null));
        assert_eq!(value.get("issue_url"), Some(&serde_json::Value::Null));
        assert_eq!(value.get("pr_url"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn workspace_pair_analysis_roundtrips_nested_overlap_payloads() {
        let workspace_a = Uuid::new_v4();
        let workspace_b = Uuid::new_v4();
        let changed_in = Uuid::new_v4();

        let analysis = WorkspacePairAnalysis {
            workspace_a,
            workspace_b,
            score: OrthogonalityScore::Red,
            overlaps: vec![
                Overlap::Hunk {
                    path: PathBuf::from("src/lib.ts"),
                    a_range: LineRange { start: 10, end: 20 },
                    b_range: LineRange { start: 18, end: 30 },
                    distance: 0,
                },
                Overlap::Dependency {
                    changed_in,
                    changed_file: PathBuf::from("src/api/client.ts"),
                    changed_export: ExportDelta::SignatureChanged {
                        symbol_name: "fetchUser".to_string(),
                        old: Signature {
                            text: "fn fetchUser(id: string)".to_string(),
                        },
                        new: Signature {
                            text: "fn fetchUser(id: string, retries: u8)".to_string(),
                        },
                    },
                    affected_file: PathBuf::from("src/consumer.ts"),
                    affected_usage: vec![Location {
                        file: PathBuf::from("src/consumer.ts"),
                        line: 42,
                        column: 5,
                    }],
                },
            ],
            merge_order_hint: MergeOrder::NeedsCoordination,
            last_computed: Utc.timestamp_opt(1_700_000_000, 123_456_789).unwrap(),
        };

        let encoded = serde_json::to_string(&analysis).unwrap();
        let decoded: WorkspacePairAnalysis = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded.workspace_a, workspace_a);
        assert_eq!(decoded.workspace_b, workspace_b);
        assert_eq!(decoded.score, OrthogonalityScore::Red);
        assert_eq!(decoded.merge_order_hint, MergeOrder::NeedsCoordination);
        assert_eq!(decoded.last_computed, analysis.last_computed);
        assert_eq!(decoded.overlaps.len(), 2);
        assert_eq!(decoded.overlaps[0].severity(), OrthogonalityScore::Red);
        assert_eq!(decoded.overlaps[1].severity(), OrthogonalityScore::Black);

        match &decoded.overlaps[1] {
            Overlap::Dependency {
                changed_in: decoded_changed_in,
                changed_file,
                changed_export,
                affected_file,
                affected_usage,
            } => {
                assert_eq!(*decoded_changed_in, changed_in);
                assert_eq!(changed_file, &PathBuf::from("src/api/client.ts"));
                assert_eq!(affected_file, &PathBuf::from("src/consumer.ts"));
                assert_eq!(affected_usage.len(), 1);
                match changed_export {
                    ExportDelta::SignatureChanged {
                        symbol_name,
                        old,
                        new,
                    } => {
                        assert_eq!(symbol_name, "fetchUser");
                        assert!(old.text.contains("id: string"));
                        assert!(new.text.contains("retries: u8"));
                    }
                    other => panic!("unexpected export delta after roundtrip: {other:?}"),
                }
            }
            other => panic!("unexpected overlap variant after roundtrip: {other:?}"),
        }
    }

    #[test]
    fn overlap_deserialization_requires_known_tag() {
        let payload = json!({
            "UnknownKind": {
                "path": "a.ts"
            }
        });

        let err = serde_json::from_value::<Overlap>(payload).unwrap_err();
        assert!(err.to_string().contains("unknown variant"));
    }
}
