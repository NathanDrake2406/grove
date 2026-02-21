use crate::diff::{compute_file_overlaps, compute_hunk_overlaps};
use crate::schema::compute_schema_overlaps;
use crate::types::*;
use chrono::{DateTime, Utc};

const HUNK_PROXIMITY_THRESHOLD: u32 = 5;

/// Compute symbol overlaps by comparing symbols_modified in files touched by both.
///
/// Symbols must share the same name AND have overlapping line ranges to be
/// considered the same entity. Same-named symbols in disjoint code regions
/// (e.g., `Auth::handle` vs `Billing::handle`) are distinct and not flagged.
pub fn compute_symbol_overlaps(a: &WorkspaceChangeset, b: &WorkspaceChangeset) -> Vec<Overlap> {
    let mut overlaps = Vec::new();

    for a_file in &a.changed_files {
        if let Some(b_file) = b.changed_files.iter().find(|f| f.path == a_file.path) {
            for a_sym in &a_file.symbols_modified {
                for b_sym in &b_file.symbols_modified {
                    if a_sym.name == b_sym.name && a_sym.range.overlaps(&b_sym.range) {
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
                let strategies: Vec<_> =
                    chosen_paths.into_iter().map(arb_file_change_for).collect();

                (strategies, 0u32..10u32, 0u32..10u32).prop_map(
                    |(changed_files, commits_ahead, commits_behind)| WorkspaceChangeset {
                        workspace_id: Uuid::new_v4(),
                        merge_base: "abc123".into(),
                        changed_files,
                        commits_ahead,
                        commits_behind,
                    },
                )
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

    fn expect_symbol_overlap(overlap: &Overlap) -> (&PathBuf, &str) {
        match overlap {
            Overlap::Symbol {
                path, symbol_name, ..
            } => (path, symbol_name),
            Overlap::File { .. }
            | Overlap::Hunk { .. }
            | Overlap::Dependency { .. }
            | Overlap::Schema { .. } => panic!("expected symbol overlap"),
        }
    }

    fn make_symbol(name: &str, kind: SymbolKind, start: u32, end: u32) -> Symbol {
        Symbol {
            name: name.to_string(),
            kind,
            range: LineRange { start, end },
            signature: None,
        }
    }

    fn make_file(path: &str, hunks: Vec<Hunk>, symbols_modified: Vec<Symbol>) -> FileChange {
        FileChange {
            path: PathBuf::from(path),
            change_type: ChangeType::Modified,
            hunks,
            symbols_modified,
            exports_changed: vec![],
        }
    }

    fn low_noise_case_violations(
        case_name: &str,
        analysis: &WorkspacePairAnalysis,
        allow_symbol_overlap: bool,
    ) -> Vec<String> {
        let mut failures = Vec::new();

        if analysis.score > OrthogonalityScore::Yellow {
            failures.push(format!(
                "{case_name}: expected score <= Yellow, got {:?} with overlaps {:?}",
                analysis.score, analysis.overlaps
            ));
        }

        if !allow_symbol_overlap {
            let symbol_overlap_count = analysis
                .overlaps
                .iter()
                .filter(|overlap| matches!(overlap, Overlap::Symbol { .. }))
                .count();
            if symbol_overlap_count != 0 {
                failures.push(format!(
                    "{case_name}: expected no symbol overlaps, got {:?}",
                    analysis.overlaps
                ));
            }
        }

        failures
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
                // Use a fixed range per symbol name so same-named symbols overlap
                let sym_idx = i % 2;
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
                            name: format!("sym{sym_idx}"),
                            kind: SymbolKind::Function,
                            range: LineRange {
                                start: sym_idx * 50 + 1,
                                end: sym_idx * 50 + 10,
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
        // Ranges must overlap for a symbol overlap to be reported —
        // this tests that kind mismatch alone doesn't prevent detection.
        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![Symbol {
                    name: "token".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 25 },
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
        let (path, symbol_name) = expect_symbol_overlap(&overlaps[0]);
        assert_eq!(path, &PathBuf::from("src/shared.ts"));
        assert_eq!(symbol_name, "token");
    }

    #[test]
    fn adversarial_non_conflicting_scenarios_should_stay_at_or_below_yellow() {
        struct LowNoiseCase {
            name: &'static str,
            a: WorkspaceChangeset,
            b: WorkspaceChangeset,
            allow_symbol_overlap: bool,
        }

        let cases = vec![
            LowNoiseCase {
                name: "same_name_function_disjoint_ranges_same_file",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/service.ts",
                        vec![Hunk {
                            old_start: 10,
                            old_lines: 3,
                            new_start: 10,
                            new_lines: 3,
                        }],
                        vec![make_symbol("handle", SymbolKind::Function, 10, 12)],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/service.ts",
                        vec![Hunk {
                            old_start: 160,
                            old_lines: 4,
                            new_start: 160,
                            new_lines: 4,
                        }],
                        vec![make_symbol("handle", SymbolKind::Function, 160, 163)],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "same_name_different_kind_disjoint_ranges_same_file",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/service.ts",
                        vec![Hunk {
                            old_start: 20,
                            old_lines: 2,
                            new_start: 20,
                            new_lines: 2,
                        }],
                        vec![make_symbol("token", SymbolKind::Class, 20, 21)],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/service.ts",
                        vec![Hunk {
                            old_start: 210,
                            old_lines: 3,
                            new_start: 210,
                            new_lines: 3,
                        }],
                        vec![make_symbol("token", SymbolKind::Function, 210, 212)],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "same_method_name_in_different_impl_regions",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/domain.rs",
                        vec![Hunk {
                            old_start: 35,
                            old_lines: 5,
                            new_start: 35,
                            new_lines: 6,
                        }],
                        vec![make_symbol("execute", SymbolKind::Method, 34, 42)],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/domain.rs",
                        vec![Hunk {
                            old_start: 230,
                            old_lines: 4,
                            new_start: 230,
                            new_lines: 5,
                        }],
                        vec![make_symbol("execute", SymbolKind::Method, 228, 236)],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "same_file_near_threshold_but_independent_hunks",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/threshold.ts",
                        vec![Hunk {
                            old_start: 10,
                            old_lines: 4,
                            new_start: 10,
                            new_lines: 4,
                        }],
                        vec![],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/threshold.ts",
                        vec![Hunk {
                            old_start: 18,
                            old_lines: 3,
                            new_start: 18,
                            new_lines: 3,
                        }],
                        vec![],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "same_file_outside_hunk_threshold_independent",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/threshold.ts",
                        vec![Hunk {
                            old_start: 10,
                            old_lines: 4,
                            new_start: 10,
                            new_lines: 4,
                        }],
                        vec![],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/threshold.ts",
                        vec![Hunk {
                            old_start: 22,
                            old_lines: 3,
                            new_start: 22,
                            new_lines: 3,
                        }],
                        vec![],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "independent_import_refactors_same_file",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/parser.ts",
                        vec![Hunk {
                            old_start: 5,
                            old_lines: 2,
                            new_start: 5,
                            new_lines: 2,
                        }],
                        vec![make_symbol("parseImports", SymbolKind::Function, 40, 65)],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/parser.ts",
                        vec![Hunk {
                            old_start: 120,
                            old_lines: 2,
                            new_start: 120,
                            new_lines: 2,
                        }],
                        vec![make_symbol(
                            "resolveImports",
                            SymbolKind::Function,
                            150,
                            180,
                        )],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "independent_constants_with_no_shared_symbol_names",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/constants.ts",
                        vec![Hunk {
                            old_start: 12,
                            old_lines: 1,
                            new_start: 12,
                            new_lines: 1,
                        }],
                        vec![make_symbol("MAX_RETRIES", SymbolKind::Constant, 12, 12)],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/constants.ts",
                        vec![Hunk {
                            old_start: 80,
                            old_lines: 1,
                            new_start: 80,
                            new_lines: 1,
                        }],
                        vec![make_symbol(
                            "DEFAULT_TIMEOUT_MS",
                            SymbolKind::Constant,
                            80,
                            80,
                        )],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "large_file_many_unique_symbols_do_not_escalate",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/large.ts",
                        vec![Hunk {
                            old_start: 30,
                            old_lines: 3,
                            new_start: 30,
                            new_lines: 3,
                        }],
                        (0..30)
                            .map(|i| {
                                make_symbol(
                                    &format!("a_symbol_{i}"),
                                    SymbolKind::Function,
                                    i * 5 + 1,
                                    i * 5 + 2,
                                )
                            })
                            .collect(),
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/large.ts",
                        vec![Hunk {
                            old_start: 260,
                            old_lines: 3,
                            new_start: 260,
                            new_lines: 3,
                        }],
                        (0..30)
                            .map(|i| {
                                make_symbol(
                                    &format!("b_symbol_{i}"),
                                    SymbolKind::Function,
                                    i * 6 + 200,
                                    i * 6 + 201,
                                )
                            })
                            .collect(),
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "same_file_multi_hunk_independent_edits",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/handler.ts",
                        vec![
                            Hunk {
                                old_start: 10,
                                old_lines: 2,
                                new_start: 10,
                                new_lines: 2,
                            },
                            Hunk {
                                old_start: 260,
                                old_lines: 3,
                                new_start: 260,
                                new_lines: 3,
                            },
                        ],
                        vec![
                            make_symbol("buildAuthHeaders", SymbolKind::Function, 10, 20),
                            make_symbol("serializeTrace", SymbolKind::Function, 260, 282),
                        ],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/handler.ts",
                        vec![
                            Hunk {
                                old_start: 80,
                                old_lines: 2,
                                new_start: 80,
                                new_lines: 2,
                            },
                            Hunk {
                                old_start: 340,
                                old_lines: 3,
                                new_start: 340,
                                new_lines: 3,
                            },
                        ],
                        vec![
                            make_symbol("parseRequestId", SymbolKind::Function, 80, 95),
                            make_symbol("emitMetrics", SymbolKind::Function, 340, 360),
                        ],
                    )],
                ),
                allow_symbol_overlap: false,
            },
            LowNoiseCase {
                name: "same_symbol_name_across_different_files_is_safe",
                a: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/a.ts",
                        vec![Hunk {
                            old_start: 8,
                            old_lines: 2,
                            new_start: 8,
                            new_lines: 2,
                        }],
                        vec![make_symbol("bootstrap", SymbolKind::Function, 8, 15)],
                    )],
                ),
                b: make_changeset_with_id(
                    Uuid::new_v4(),
                    vec![make_file(
                        "src/b.ts",
                        vec![Hunk {
                            old_start: 8,
                            old_lines: 2,
                            new_start: 8,
                            new_lines: 2,
                        }],
                        vec![make_symbol("bootstrap", SymbolKind::Function, 8, 15)],
                    )],
                ),
                allow_symbol_overlap: false,
            },
        ];

        let mut failures = Vec::new();
        for case in cases {
            let analysis = score_pair(&case.a, &case.b, vec![]);
            failures.extend(low_noise_case_violations(
                case.name,
                &analysis,
                case.allow_symbol_overlap,
            ));
        }
        assert!(
            failures.is_empty(),
            "low-noise adversarial cases failed:\n{}",
            failures.join("\n")
        );
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
                    range: LineRange { start: 10, end: 20 },
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
                    range: LineRange { start: 15, end: 24 },
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

    // === Stress tests and edge cases ===

    #[test]
    fn hundred_files_per_workspace_all_overlapping() {
        let files: Vec<FileChange> = (0..100)
            .map(|i| FileChange {
                path: PathBuf::from(format!("src/module_{i}.ts")),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            })
            .collect();

        let a = make_changeset_with_id(Uuid::new_v4(), files.clone());
        let b = make_changeset_with_id(Uuid::new_v4(), files);

        let result = score_pair(&a, &b, vec![]);

        let file_overlap_count = result
            .overlaps
            .iter()
            .filter(|o| matches!(o, Overlap::File { .. }))
            .count();
        assert_eq!(file_overlap_count, 100);
        assert!(result.score >= OrthogonalityScore::Yellow);
    }

    #[test]
    fn many_symbols_same_file() {
        let symbols_a: Vec<Symbol> = (0..50)
            .map(|i| Symbol {
                name: format!("sym_{i}"),
                kind: SymbolKind::Function,
                range: LineRange {
                    start: i * 10,
                    end: i * 10 + 5,
                },
                signature: None,
            })
            .collect();

        let symbols_b: Vec<Symbol> = (0..50)
            .map(|i| Symbol {
                name: format!("sym_{i}"),
                kind: SymbolKind::Method,
                range: LineRange {
                    start: i * 10,
                    end: i * 10 + 8,
                },
                signature: None,
            })
            .collect();

        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/big_module.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: symbols_a,
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/big_module.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: symbols_b,
                exports_changed: vec![],
            }],
        );

        let symbol_overlaps = compute_symbol_overlaps(&a, &b);
        assert_eq!(symbol_overlaps.len(), 50);

        for overlap in &symbol_overlaps {
            let (path, _) = expect_symbol_overlap(overlap);
            assert_eq!(path, &PathBuf::from("src/big_module.ts"));
        }
    }

    #[test]
    fn empty_changesets_score_green() {
        let a = make_changeset_with_id(Uuid::new_v4(), vec![]);
        let b = make_changeset_with_id(Uuid::new_v4(), vec![]);

        let result = score_pair(&a, &b, vec![]);
        assert_eq!(result.score, OrthogonalityScore::Green);
        assert!(result.overlaps.is_empty());
    }

    #[test]
    fn single_file_no_hunks_scores_yellow() {
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

        let result = score_pair(&a, &b, vec![]);
        assert_eq!(result.score, OrthogonalityScore::Yellow);
    }

    #[test]
    fn score_is_deterministic() {
        let a = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 10,
                    old_lines: 5,
                    new_start: 10,
                    new_lines: 5,
                }],
                symbols_modified: vec![Symbol {
                    name: "handler".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 10, end: 14 },
                    signature: None,
                }],
                exports_changed: vec![],
            }],
        );
        let b = make_changeset_with_id(
            Uuid::new_v4(),
            vec![FileChange {
                path: PathBuf::from("src/shared.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![Hunk {
                    old_start: 12,
                    old_lines: 3,
                    new_start: 12,
                    new_lines: 3,
                }],
                symbols_modified: vec![Symbol {
                    name: "handler".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 12, end: 14 },
                    signature: None,
                }],
                exports_changed: vec![],
            }],
        );

        let first = score_pair(&a, &b, vec![]);
        let second = score_pair(&a, &b, vec![]);

        assert_eq!(first.score, second.score);
        assert_eq!(first.overlaps.len(), second.overlaps.len());
        assert_eq!(first.merge_order_hint, second.merge_order_hint);
    }
}
