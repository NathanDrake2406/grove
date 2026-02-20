use crate::diff::{compute_file_overlaps, compute_hunk_overlaps};
use crate::schema::compute_schema_overlaps;
use crate::types::*;
use chrono::{DateTime, Utc};

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
    last_computed: DateTime<Utc>,
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
        last_computed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn deterministic_timestamp() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).expect("valid fixed timestamp")
    }

    fn score_pair(
        a: &WorkspaceChangeset,
        b: &WorkspaceChangeset,
        dependency_overlaps: Vec<Overlap>,
    ) -> WorkspacePairAnalysis {
        super::score_pair(a, b, dependency_overlaps, deterministic_timestamp())
    }

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
                hunks: vec![Hunk {
                    old_start: 1,
                    old_lines: 5,
                    new_start: 1,
                    new_lines: 5,
                }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/payment.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 1,
                    old_lines: 5,
                    new_start: 1,
                    new_lines: 5,
                }],
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
                hunks: vec![Hunk {
                    old_start: 1,
                    old_lines: 5,
                    new_start: 1,
                    new_lines: 5,
                }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 100,
                    old_lines: 5,
                    new_start: 100,
                    new_lines: 5,
                }],
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
                hunks: vec![Hunk {
                    old_start: 10,
                    old_lines: 20,
                    new_start: 10,
                    new_lines: 25,
                }],
                symbols_modified: vec![shared_symbol.clone()],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/payment.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 15,
                    old_lines: 10,
                    new_start: 15,
                    new_lines: 12,
                }],
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
                old: Signature {
                    text: "fn authenticate() -> bool".into(),
                },
                new: Signature {
                    text: "fn authenticate(token: &str) -> Result<bool>".into(),
                },
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

    #[test]
    fn scoring_is_symmetric_for_workspace_order() {
        let file = |name: &str, range_start: u32| FileChange {
            path: PathBuf::from(name),
            change_type: ChangeType::Modified,
            hunks: vec![Hunk {
                old_start: range_start,
                old_lines: 3,
                new_start: range_start,
                new_lines: 3,
            }],
            symbols_modified: vec![Symbol {
                name: "same_symbol".to_string(),
                kind: SymbolKind::Function,
                range: LineRange {
                    start: range_start,
                    end: range_start + 2,
                },
                signature: None,
            }],
            exports_changed: vec![],
        };

        let a = make_changeset_with_id(Uuid::new_v4(), vec![file("src/shared.ts", 10)]);
        let b = make_changeset_with_id(Uuid::new_v4(), vec![file("src/shared.ts", 11)]);

        let ab = score_pair(&a, &b, vec![]);
        let ba = score_pair(&b, &a, vec![]);

        assert_eq!(ab.score, ba.score);
    }

    #[test]
    fn adding_more_overlaps_never_decreases_score() {
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

        let base = score_pair(&a, &b, vec![]);
        let with_dependency = score_pair(
            &a,
            &b,
            vec![Overlap::Dependency {
                changed_in: a.workspace_id,
                changed_file: PathBuf::from("src/shared.ts"),
                changed_export: ExportDelta::Added(Symbol {
                    name: "x".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 1 },
                    signature: None,
                }),
                affected_file: PathBuf::from("src/consumer.ts"),
                affected_usage: vec![],
            }],
        );

        assert!(with_dependency.score >= base.score);
    }

    #[test]
    fn ten_workspaces_all_pairs_produce_non_green_scores() {
        let workspaces: Vec<WorkspaceChangeset> = (0..10)
            .map(|i| {
                make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![FileChange {
                        path: PathBuf::from("src/shared.ts"),
                        change_type: ChangeType::Modified,
                        hunks: vec![Hunk {
                            old_start: i * 10 + 1,
                            old_lines: 2,
                            new_start: i * 10 + 1,
                            new_lines: 2,
                        }],
                        symbols_modified: vec![Symbol {
                            name: format!("sym{}", i % 2),
                            kind: SymbolKind::Function,
                            range: LineRange {
                                start: i * 10 + 1,
                                end: i * 10 + 2,
                            },
                            signature: None,
                        }],
                        exports_changed: vec![],
                    }],
                )
            })
            .collect();

        let mut pair_count = 0usize;
        let mut saw_yellow = false;
        let mut saw_red = false;
        let mut saw_black = false;
        for i in 0..workspaces.len() {
            for j in (i + 1)..workspaces.len() {
                let dep = if (i + j) % 5 == 0 {
                    vec![Overlap::Dependency {
                        changed_in: workspaces[i].workspace_id,
                        changed_file: PathBuf::from("src/dep.ts"),
                        changed_export: ExportDelta::Added(Symbol {
                            name: "new_dep".into(),
                            kind: SymbolKind::Function,
                            range: LineRange { start: 1, end: 1 },
                            signature: None,
                        }),
                        affected_file: PathBuf::from("src/consumer.ts"),
                        affected_usage: vec![],
                    }]
                } else {
                    vec![]
                };

                let analysis = score_pair(&workspaces[i], &workspaces[j], dep);
                pair_count += 1;
                assert_ne!(analysis.score, OrthogonalityScore::Green);
                match analysis.score {
                    OrthogonalityScore::Yellow => saw_yellow = true,
                    OrthogonalityScore::Red => saw_red = true,
                    OrthogonalityScore::Black => saw_black = true,
                    OrthogonalityScore::Green => {}
                }
            }
        }

        assert_eq!(pair_count, 45);
        assert!(saw_yellow);
        assert!(saw_red);
        assert!(saw_black);
    }

    #[test]
    fn symbol_overlap_requires_same_path_even_when_names_match() {
        let symbol_a = Symbol {
            name: "shared_name".into(),
            kind: SymbolKind::Function,
            range: LineRange { start: 1, end: 2 },
            signature: None,
        };
        let symbol_b = Symbol {
            name: "shared_name".into(),
            kind: SymbolKind::Function,
            range: LineRange { start: 10, end: 12 },
            signature: None,
        };

        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/a.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![symbol_a],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/b.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![symbol_b],
                exports_changed: vec![],
            }],
        );

        let overlaps = compute_symbol_overlaps(&a, &b);
        assert!(overlaps.is_empty());
    }

    #[test]
    fn symbol_overlap_matches_name_even_when_symbol_kind_differs() {
        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![Symbol {
                    name: "token".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 5 },
                    signature: Some("function token()".into()),
                }],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![Symbol {
                    name: "token".into(),
                    kind: SymbolKind::Class,
                    range: LineRange { start: 20, end: 40 },
                    signature: None,
                }],
                exports_changed: vec![],
            }],
        );

        let overlaps = compute_symbol_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Symbol {
                path, symbol_name, ..
            } => {
                assert_eq!(path, &PathBuf::from("src/shared.ts"));
                assert_eq!(symbol_name, "token");
            }
            _ => panic!("expected symbol overlap"),
        }
    }

    #[test]
    fn merge_order_hint_prefers_smaller_changeset_when_not_black() {
        let one_file = vec![FileChange {
            path: PathBuf::from("src/a.ts"),
            change_type: ChangeType::Modified,
            hunks: vec![],
            symbols_modified: vec![],
            exports_changed: vec![],
        }];
        let three_files = vec![
            FileChange {
                path: PathBuf::from("src/b.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            },
            FileChange {
                path: PathBuf::from("src/c.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            },
            FileChange {
                path: PathBuf::from("src/d.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            },
        ];

        let a = make_changeset_with_id(Uuid::new_v4(), one_file);
        let b = make_changeset_with_id(Uuid::new_v4(), three_files);

        let ab = score_pair(&a, &b, vec![]);
        let ba = score_pair(&b, &a, vec![]);

        assert_ne!(ab.score, OrthogonalityScore::Black);
        assert_ne!(ba.score, OrthogonalityScore::Black);
        assert_eq!(ab.merge_order_hint, MergeOrder::AFirst);
        assert_eq!(ba.merge_order_hint, MergeOrder::BFirst);
    }

    #[test]
    fn black_score_forces_needs_coordination_merge_hint() {
        let a = make_changeset_with_id(Uuid::new_v4(), vec![]);
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/large_feature.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );

        let dep_overlaps = vec![Overlap::Dependency {
            changed_in: a.workspace_id,
            changed_file: PathBuf::from("src/core.ts"),
            changed_export: ExportDelta::Added(Symbol {
                name: "core".into(),
                kind: SymbolKind::Function,
                range: LineRange { start: 1, end: 1 },
                signature: None,
            }),
            affected_file: PathBuf::from("src/large_feature.ts"),
            affected_usage: vec![],
        }];

        let result = score_pair(&a, &b, dep_overlaps.clone());
        assert_eq!(result.score, OrthogonalityScore::Black);
        assert_eq!(result.merge_order_hint, MergeOrder::NeedsCoordination);
        assert!(result.overlaps.len() >= dep_overlaps.len());
    }

    #[test]
    fn staged_overlap_escalation_is_monotonic_green_to_black() {
        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();

        let green_a = make_changeset_with_id(
            a_id,
            vec![FileChange {
                path: PathBuf::from("src/a_only.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let green_b = make_changeset_with_id(
            b_id,
            vec![FileChange {
                path: PathBuf::from("src/b_only.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let green = score_pair(&green_a, &green_b, vec![]);

        let yellow_a = make_changeset_with_id(
            a_id,
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 1,
                    old_lines: 1,
                    new_start: 1,
                    new_lines: 1,
                }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let yellow_b = make_changeset_with_id(
            b_id,
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 100,
                    old_lines: 1,
                    new_start: 100,
                    new_lines: 1,
                }],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
        );
        let yellow = score_pair(&yellow_a, &yellow_b, vec![]);

        let red_a = make_changeset_with_id(
            a_id,
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![Symbol {
                    name: "same".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 10, end: 12 },
                    signature: None,
                }],
                exports_changed: vec![],
            }],
        );
        let red_b = make_changeset_with_id(
            b_id,
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![Symbol {
                    name: "same".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 20, end: 24 },
                    signature: None,
                }],
                exports_changed: vec![],
            }],
        );
        let red = score_pair(&red_a, &red_b, vec![]);

        let black = score_pair(
            &red_a,
            &red_b,
            vec![Overlap::Dependency {
                changed_in: a_id,
                changed_file: PathBuf::from("src/shared.ts"),
                changed_export: ExportDelta::Added(Symbol {
                    name: "same".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 1 },
                    signature: None,
                }),
                affected_file: PathBuf::from("src/consumer.ts"),
                affected_usage: vec![],
            }],
        );

        assert_eq!(green.score, OrthogonalityScore::Green);
        assert_eq!(yellow.score, OrthogonalityScore::Yellow);
        assert_eq!(red.score, OrthogonalityScore::Red);
        assert_eq!(black.score, OrthogonalityScore::Black);

        assert!(yellow.score >= green.score);
        assert!(red.score >= yellow.score);
        assert!(black.score >= red.score);
    }

    #[test]
    fn large_pairwise_score_symmetry_and_internal_max_invariant() {
        let workspaces: Vec<WorkspaceChangeset> = (0..18)
            .map(|i| {
                make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![
                        FileChange {
                            path: PathBuf::from(format!("src/shared_{}.ts", i % 4)),
                            change_type: ChangeType::Modified,
                            hunks: vec![Hunk {
                                old_start: (i * 3 + 1) as u32,
                                old_lines: 2,
                                new_start: (i * 3 + 1) as u32,
                                new_lines: 2,
                            }],
                            symbols_modified: vec![Symbol {
                                name: format!("sym_{}", i % 5),
                                kind: SymbolKind::Function,
                                range: LineRange {
                                    start: (i * 3 + 1) as u32,
                                    end: (i * 3 + 2) as u32,
                                },
                                signature: None,
                            }],
                            exports_changed: vec![],
                        },
                        FileChange {
                            path: PathBuf::from(format!("src/isolated_{}.ts", i)),
                            change_type: ChangeType::Modified,
                            hunks: vec![],
                            symbols_modified: vec![],
                            exports_changed: vec![],
                        },
                    ],
                )
            })
            .collect();

        for i in 0..workspaces.len() {
            for j in (i + 1)..workspaces.len() {
                let ab = score_pair(&workspaces[i], &workspaces[j], vec![]);
                let ba = score_pair(&workspaces[j], &workspaces[i], vec![]);

                assert_eq!(ab.score, ba.score);
                assert_eq!(ab.overlaps.len(), ba.overlaps.len());

                let max_from_overlaps = ab
                    .overlaps
                    .iter()
                    .map(Overlap::severity)
                    .max()
                    .unwrap_or(OrthogonalityScore::Green);
                assert_eq!(ab.score, max_from_overlaps);
            }
        }
    }
}
