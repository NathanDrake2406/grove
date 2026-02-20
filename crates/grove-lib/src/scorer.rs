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

    // ── Property-based tests ──────────────────────────────────────────────────
    //
    // These use proptest to verify invariants that must hold for all possible
    // WorkspaceChangeset inputs, not just the hand-crafted cases above.

    #[cfg(test)]
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        // ── Strategies ────────────────────────────────────────────────────────

        fn arb_line_range() -> impl Strategy<Value = LineRange> {
            (0u32..10_000u32).prop_flat_map(|start| {
                (0u32..500u32).prop_map(move |width| LineRange {
                    start,
                    end: start + width,
                })
            })
        }

        fn arb_hunk() -> impl Strategy<Value = Hunk> {
            (0u32..5_000u32, 0u32..200u32, 0u32..5_000u32, 0u32..200u32).prop_map(
                |(old_start, old_lines, new_start, new_lines)| Hunk {
                    old_start,
                    old_lines,
                    new_start,
                    new_lines,
                },
            )
        }

        fn arb_symbol_kind() -> impl Strategy<Value = SymbolKind> {
            prop_oneof![
                Just(SymbolKind::Function),
                Just(SymbolKind::Class),
                Just(SymbolKind::Interface),
                Just(SymbolKind::TypeAlias),
                Just(SymbolKind::Enum),
                Just(SymbolKind::Constant),
                Just(SymbolKind::Variable),
                Just(SymbolKind::Method),
            ]
        }

        fn arb_symbol(name: impl Strategy<Value = String>) -> impl Strategy<Value = Symbol> {
            (name, arb_symbol_kind(), arb_line_range()).prop_map(|(n, kind, range)| Symbol {
                name: n,
                kind,
                range,
                signature: None,
            })
        }

        fn arb_change_type() -> impl Strategy<Value = ChangeType> {
            prop_oneof![
                Just(ChangeType::Added),
                Just(ChangeType::Modified),
                Just(ChangeType::Deleted),
                Just(ChangeType::Renamed),
            ]
        }

        fn arb_file_path() -> impl Strategy<Value = PathBuf> {
            prop_oneof![
                Just(PathBuf::from("src/shared.ts")),
                Just(PathBuf::from("src/auth.ts")),
                Just(PathBuf::from("src/payment.ts")),
                Just(PathBuf::from("src/utils.ts")),
            ]
        }

        fn arb_symbol_name() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("processPayment".to_string()),
                Just("authenticate".to_string()),
                Just("formatUser".to_string()),
                Just("DataStore".to_string()),
            ]
        }

        fn arb_file_change_for(path: PathBuf) -> impl Strategy<Value = FileChange> {
            (
                arb_change_type(),
                prop::collection::vec(arb_hunk(), 0..4),
                prop::collection::vec(arb_symbol(arb_symbol_name()), 0..3),
            )
                .prop_map(move |(change_type, hunks, symbols_modified)| FileChange {
                    path: path.clone(),
                    change_type,
                    hunks,
                    symbols_modified,
                    exports_changed: vec![],
                })
        }

        // Generates a changeset with *unique* file paths to avoid duplicate-path
        // ambiguity in the scorer (which uses `Iterator::find` on changed_files).
        // Duplicate paths in a real changeset are invalid; we produce canonical inputs.
        fn arb_changeset() -> impl Strategy<Value = WorkspaceChangeset> {
            // Fixed pool of 4 unique paths; generate 0..=4 distinct entries
            let paths: [PathBuf; 4] = [
                PathBuf::from("src/shared.ts"),
                PathBuf::from("src/auth.ts"),
                PathBuf::from("src/payment.ts"),
                PathBuf::from("src/utils.ts"),
            ];

            // Choose how many files to include (subset of pool by index)
            (0usize..=4usize).prop_flat_map(move |count| {
                let chosen_paths: Vec<PathBuf> = paths[..count].to_vec();
                let strategies: Vec<_> = chosen_paths
                    .into_iter()
                    .map(arb_file_change_for)
                    .collect();

                (
                    strategies,
                    0u32..10u32,
                    0u32..10u32,
                )
                    .prop_map(|(changed_files, commits_ahead, commits_behind)| {
                        WorkspaceChangeset {
                            workspace_id: Uuid::new_v4(),
                            merge_base: "abc123".into(),
                            changed_files,
                            commits_ahead,
                            commits_behind,
                        }
                    })
            })
        }

        fn ts() -> DateTime<Utc> {
            DateTime::from_timestamp(1_700_000_000, 0).expect("fixed timestamp")
        }

        // ── Property: score_pair is symmetric ────────────────────────────────
        //
        // score_pair(a, b) and score_pair(b, a) must produce the same
        // OrthogonalityScore for any input pair. The merge_order_hint may
        // differ (AFirst vs BFirst), but the conflict severity cannot.
        //
        // Note: overlap *count* is not required to be symmetric because the
        // input may have duplicate file paths in `changed_files`, which causes
        // the Cartesian product of matching entries to differ depending on
        // which side is `a` vs `b`. The score (max severity) is the invariant.
        proptest! {
            #[test]
            fn prop_score_pair_is_symmetric(a in arb_changeset(), b in arb_changeset()) {
                let ab = super::super::score_pair(&a, &b, vec![], ts());
                let ba = super::super::score_pair(&b, &a, vec![], ts());
                prop_assert_eq!(ab.score, ba.score,
                    "score_pair must be symmetric: score(a,b)={:?} != score(b,a)={:?}",
                    ab.score, ba.score);
            }
        }

        // ── Property: score is monotone — adding overlaps never decreases it ─
        //
        // If we start with a pair's score and then add a dependency overlap,
        // the resulting score must be >= the original. Scores are ordered:
        // Green < Yellow < Red < Black.
        proptest! {
            #[test]
            fn prop_adding_dependency_overlap_never_decreases_score(
                a in arb_changeset(),
                b in arb_changeset(),
            ) {
                let base_score = super::super::score_pair(&a, &b, vec![], ts()).score;

                // A dependency overlap always adds a Black-severity item
                let dep = vec![Overlap::Dependency {
                    changed_in: a.workspace_id,
                    changed_file: PathBuf::from("src/dep.ts"),
                    changed_export: ExportDelta::Added(Symbol {
                        name: "newExport".into(),
                        kind: SymbolKind::Function,
                        range: LineRange { start: 1, end: 1 },
                        signature: None,
                    }),
                    affected_file: PathBuf::from("src/consumer.ts"),
                    affected_usage: vec![],
                }];
                let higher_score = super::super::score_pair(&a, &b, dep, ts()).score;

                prop_assert!(higher_score >= base_score,
                    "adding a dependency overlap must not decrease score: \
                     base={:?} higher={:?}", base_score, higher_score);
                // With a dependency overlap, the result must be exactly Black
                prop_assert_eq!(higher_score, OrthogonalityScore::Black,
                    "dependency overlap must always produce Black score");
            }
        }

        // ── Property: score never exceeds Black ───────────────────────────────
        //
        // Black is the maximum severity. No combination of inputs should
        // produce a score that violates the OrthogonalityScore ordering.
        proptest! {
            #[test]
            fn prop_score_never_exceeds_black(
                a in arb_changeset(),
                b in arb_changeset(),
            ) {
                let result = super::super::score_pair(&a, &b, vec![], ts());
                prop_assert!(result.score <= OrthogonalityScore::Black,
                    "score {:?} exceeds Black (maximum)", result.score);
            }
        }

        // ── Property: score equals max severity across all overlaps ───────────
        //
        // The reported score must exactly equal the maximum severity of
        // all individual overlaps. An empty overlap list must produce Green.
        proptest! {
            #[test]
            fn prop_score_equals_max_overlap_severity(
                a in arb_changeset(),
                b in arb_changeset(),
            ) {
                let result = super::super::score_pair(&a, &b, vec![], ts());
                let expected = result
                    .overlaps
                    .iter()
                    .map(|o| o.severity())
                    .max()
                    .unwrap_or(OrthogonalityScore::Green);
                prop_assert_eq!(result.score, expected,
                    "score {:?} must equal max overlap severity {:?}",
                    result.score, expected);
            }
        }

        // ── Property: empty changesets always score Green ─────────────────────
        //
        // If both workspaces have no changed files, there can be no overlaps,
        // so the result must always be Green with zero overlaps.
        proptest! {
            #[test]
            fn prop_empty_changesets_score_green(
                _seed in 0u32..1000u32,
            ) {
                let a = WorkspaceChangeset {
                    workspace_id: Uuid::new_v4(),
                    merge_base: "abc".into(),
                    changed_files: vec![],
                    commits_ahead: 0,
                    commits_behind: 0,
                };
                let b = WorkspaceChangeset {
                    workspace_id: Uuid::new_v4(),
                    merge_base: "abc".into(),
                    changed_files: vec![],
                    commits_ahead: 0,
                    commits_behind: 0,
                };
                let result = super::super::score_pair(&a, &b, vec![], ts());
                prop_assert_eq!(result.score, OrthogonalityScore::Green,
                    "empty changesets must score Green, got {:?}", result.score);
                prop_assert!(result.overlaps.is_empty(),
                    "empty changesets must produce no overlaps, got {} overlaps",
                    result.overlaps.len());
            }
        }

        // ── Property: disjoint file sets always score Green ───────────────────
        //
        // If worktrees touch completely different files, no file-level,
        // hunk-level, or symbol-level overlaps are possible.
        proptest! {
            #[test]
            fn prop_disjoint_file_sets_score_green(
                hunks_a in prop::collection::vec(arb_hunk(), 0..5),
                hunks_b in prop::collection::vec(arb_hunk(), 0..5),
            ) {
                let a = WorkspaceChangeset {
                    workspace_id: Uuid::new_v4(),
                    merge_base: "abc".into(),
                    changed_files: vec![FileChange {
                        path: PathBuf::from("src/only_a.ts"),
                        change_type: ChangeType::Modified,
                        hunks: hunks_a,
                        symbols_modified: vec![],
                        exports_changed: vec![],
                    }],
                    commits_ahead: 1,
                    commits_behind: 0,
                };
                let b = WorkspaceChangeset {
                    workspace_id: Uuid::new_v4(),
                    merge_base: "abc".into(),
                    changed_files: vec![FileChange {
                        path: PathBuf::from("src/only_b.ts"),
                        change_type: ChangeType::Modified,
                        hunks: hunks_b,
                        symbols_modified: vec![],
                        exports_changed: vec![],
                    }],
                    commits_ahead: 1,
                    commits_behind: 0,
                };
                let result = super::super::score_pair(&a, &b, vec![], ts());
                prop_assert_eq!(result.score, OrthogonalityScore::Green,
                    "disjoint file sets must score Green, got {:?}", result.score);
                prop_assert!(result.overlaps.is_empty(),
                    "disjoint file sets must produce no overlaps, got {}: {:?}",
                    result.overlaps.len(), result.overlaps);
            }
        }
    } // mod prop_tests

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
