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
                            a_range: a_range.clone(),
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
    use std::cmp::Ordering;
    use uuid::Uuid;

    // ── Property-based tests ──────────────────────────────────────────────────

    #[cfg(test)]
    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        // ── Strategies ────────────────────────────────────────────────────────

        fn arb_hunk() -> impl Strategy<Value = Hunk> {
            // new_lines=0 produces zero-length hunks (edge case to cover)
            (0u32..10_000u32, 0u32..500u32, 0u32..10_000u32, 0u32..500u32).prop_map(
                |(old_start, old_lines, new_start, new_lines)| Hunk {
                    old_start,
                    old_lines,
                    new_start,
                    new_lines,
                },
            )
        }

        fn arb_change_type() -> impl Strategy<Value = ChangeType> {
            prop_oneof![
                Just(ChangeType::Added),
                Just(ChangeType::Modified),
                Just(ChangeType::Deleted),
                Just(ChangeType::Renamed),
            ]
        }

        fn arb_file_change_for_path(path: PathBuf) -> impl Strategy<Value = FileChange> {
            (
                arb_change_type(),
                prop::collection::vec(arb_hunk(), 0..6),
            )
                .prop_map(move |(change_type, hunks)| FileChange {
                    path: path.clone(),
                    change_type,
                    hunks,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                })
        }

        fn make_cs(files: Vec<FileChange>) -> WorkspaceChangeset {
            WorkspaceChangeset {
                workspace_id: uuid::Uuid::new_v4(),
                merge_base: "prop".into(),
                changed_files: files,
                commits_ahead: 1,
                commits_behind: 0,
            }
        }

        // ── Property: file_overlap is commutative ─────────────────────────────
        //
        // The set of overlapping file paths must be identical regardless of
        // argument order. We compare normalized (path, min_change, max_change)
        // tuples to handle field swapping.
        proptest! {
            #[test]
            fn prop_file_overlap_is_commutative(
                fc_a in arb_file_change_for_path(PathBuf::from("src/shared.ts")),
                fc_b in arb_file_change_for_path(PathBuf::from("src/shared.ts")),
                fc_only_a in arb_file_change_for_path(PathBuf::from("src/only_a.ts")),
                fc_only_b in arb_file_change_for_path(PathBuf::from("src/only_b.ts")),
            ) {
                let cs_a = make_cs(vec![fc_a, fc_only_a]);
                let cs_b = make_cs(vec![fc_b, fc_only_b]);

                fn rank(ct: ChangeType) -> u8 {
                    match ct {
                        ChangeType::Added    => 0,
                        ChangeType::Modified => 1,
                        ChangeType::Deleted  => 2,
                        ChangeType::Renamed  => 3,
                    }
                }
                fn normalize(o: &Overlap) -> (PathBuf, u8, u8) {
                    match o {
                        Overlap::File { path, a_change, b_change } => {
                            let ra = rank(*a_change);
                            let rb = rank(*b_change);
                            (path.clone(), ra.min(rb), ra.max(rb))
                        }
                        _ => panic!("unexpected overlap variant"),
                    }
                }

                let mut left: Vec<_> = compute_file_overlaps(&cs_a, &cs_b)
                    .iter().map(normalize).collect();
                let mut right: Vec<_> = compute_file_overlaps(&cs_b, &cs_a)
                    .iter().map(normalize).collect();
                left.sort();
                right.sort();

                prop_assert_eq!(&left, &right,
                    "file_overlap must be commutative: left={:?} right={:?}", left, right);
            }
        }

        // ── Property: hunk_overlap distance is commutative ────────────────────
        //
        // compute_hunk_overlaps(a, b) and compute_hunk_overlaps(b, a) must
        // produce the same set of (path, distance) pairs after normalizing
        // range order. Crucially, no panic must occur for any input.
        proptest! {
            #[test]
            fn prop_hunk_overlap_is_commutative(
                hunks_a in prop::collection::vec(arb_hunk(), 0..5),
                hunks_b in prop::collection::vec(arb_hunk(), 0..5),
                threshold in 0u32..50u32,
            ) {
                let cs_a = make_cs(vec![FileChange {
                    path: PathBuf::from("src/shared.ts"),
                    change_type: ChangeType::Modified,
                    hunks: hunks_a,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);
                let cs_b = make_cs(vec![FileChange {
                    path: PathBuf::from("src/shared.ts"),
                    change_type: ChangeType::Modified,
                    hunks: hunks_b,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);

                fn key(o: &Overlap) -> (std::path::PathBuf, u32, u32, u32, u32, u32) {
                    match o {
                        Overlap::Hunk { path, a_range, b_range, distance } => {
                            let mut ranges = [
                                (a_range.start, a_range.end),
                                (b_range.start, b_range.end),
                            ];
                            ranges.sort();
                            (path.clone(), *distance, ranges[0].0, ranges[0].1, ranges[1].0, ranges[1].1)
                        }
                        _ => panic!("unexpected overlap variant"),
                    }
                }

                let mut left: Vec<_> = compute_hunk_overlaps(&cs_a, &cs_b, threshold)
                    .iter().map(key).collect();
                let mut right: Vec<_> = compute_hunk_overlaps(&cs_b, &cs_a, threshold)
                    .iter().map(key).collect();
                left.sort();
                right.sort();

                prop_assert_eq!(&left, &right,
                    "hunk_overlap must be commutative for threshold={}", threshold);
            }
        }

        // ── Property: zero-length hunks never panic ───────────────────────────
        //
        // Hunks with new_lines=0 represent pure deletions. The distance
        // computation must handle them gracefully (no overflow, no panic).
        proptest! {
            #[test]
            fn prop_zero_length_hunks_do_not_panic(
                start_a in 0u32..50_000u32,
                start_b in 0u32..50_000u32,
                threshold in 0u32..100u32,
            ) {
                let zero_hunk_a = Hunk {
                    old_start: start_a,
                    old_lines: 1,
                    new_start: start_a,
                    new_lines: 0, // zero-length
                };
                let zero_hunk_b = Hunk {
                    old_start: start_b,
                    old_lines: 1,
                    new_start: start_b,
                    new_lines: 0, // zero-length
                };

                let cs_a = make_cs(vec![FileChange {
                    path: PathBuf::from("src/zero.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![zero_hunk_a],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);
                let cs_b = make_cs(vec![FileChange {
                    path: PathBuf::from("src/zero.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![zero_hunk_b],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);

                // Must not panic — we don't assert specific counts,
                // only that the call completes without panicking.
                let _ = compute_hunk_overlaps(&cs_a, &cs_b, threshold);
                let _ = compute_hunk_overlaps(&cs_b, &cs_a, threshold);
            }
        }

        // ── Property: hunk_overlap is monotone with threshold ─────────────────
        //
        // A strictly larger proximity threshold must produce a superset of
        // overlaps compared to a smaller threshold (superset, not necessarily
        // strict superset — equal is fine when nothing is in between).
        proptest! {
            #[test]
            fn prop_hunk_overlap_threshold_monotone(
                hunks_a in prop::collection::vec(arb_hunk(), 1..4),
                hunks_b in prop::collection::vec(arb_hunk(), 1..4),
                small_threshold in 0u32..20u32,
                extra in 0u32..20u32,
            ) {
                let large_threshold = small_threshold + extra;

                fn key(o: &Overlap) -> (u32, u32, u32, u32, u32) {
                    match o {
                        Overlap::Hunk { a_range, b_range, distance, .. } => {
                            let mut ranges = [
                                (a_range.start, a_range.end),
                                (b_range.start, b_range.end),
                            ];
                            ranges.sort();
                            (*distance, ranges[0].0, ranges[0].1, ranges[1].0, ranges[1].1)
                        }
                        _ => panic!("unexpected overlap variant"),
                    }
                }

                let cs_a = make_cs(vec![FileChange {
                    path: PathBuf::from("src/mono.ts"),
                    change_type: ChangeType::Modified,
                    hunks: hunks_a,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);
                let cs_b = make_cs(vec![FileChange {
                    path: PathBuf::from("src/mono.ts"),
                    change_type: ChangeType::Modified,
                    hunks: hunks_b,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);

                let small_set: std::collections::HashSet<_> =
                    compute_hunk_overlaps(&cs_a, &cs_b, small_threshold)
                        .iter().map(key).collect();
                let large_set: std::collections::HashSet<_> =
                    compute_hunk_overlaps(&cs_a, &cs_b, large_threshold)
                        .iter().map(key).collect();

                prop_assert!(small_set.is_subset(&large_set),
                    "threshold={small_threshold} overlaps must be a subset of \
                     threshold={large_threshold} overlaps");
            }
        }

        // ── Property: no overlaps when file sets are disjoint ─────────────────
        proptest! {
            #[test]
            fn prop_no_overlap_for_disjoint_files(
                hunks_a in prop::collection::vec(arb_hunk(), 0..5),
                hunks_b in prop::collection::vec(arb_hunk(), 0..5),
                threshold in 0u32..100u32,
            ) {
                let cs_a = make_cs(vec![FileChange {
                    path: PathBuf::from("src/only_a.ts"),
                    change_type: ChangeType::Modified,
                    hunks: hunks_a,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);
                let cs_b = make_cs(vec![FileChange {
                    path: PathBuf::from("src/only_b.ts"),
                    change_type: ChangeType::Modified,
                    hunks: hunks_b,
                    symbols_modified: vec![],
                    exports_changed: vec![],
                }]);

                let file_overlaps = compute_file_overlaps(&cs_a, &cs_b);
                let hunk_overlaps = compute_hunk_overlaps(&cs_a, &cs_b, threshold);

                prop_assert!(file_overlaps.is_empty(),
                    "disjoint files must produce no file overlaps");
                prop_assert!(hunk_overlaps.is_empty(),
                    "disjoint files must produce no hunk overlaps, \
                     got {} at threshold={threshold}", hunk_overlaps.len());
            }
        }
    } // mod prop_tests

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
            vec![Hunk {
                old_start: 10,
                old_lines: 10,
                new_start: 10,
                new_lines: 20,
            }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk {
                old_start: 20,
                old_lines: 10,
                new_start: 20,
                new_lines: 25,
            }],
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
            vec![Hunk {
                old_start: 10,
                old_lines: 5,
                new_start: 10,
                new_lines: 5,
            }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk {
                old_start: 18,
                old_lines: 5,
                new_start: 18,
                new_lines: 5,
            }],
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
            vec![Hunk {
                old_start: 10,
                old_lines: 5,
                new_start: 10,
                new_lines: 5,
            }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/payment.ts",
            vec![Hunk {
                old_start: 200,
                old_lines: 5,
                new_start: 200,
                new_lines: 5,
            }],
        )]);

        let overlaps = compute_hunk_overlaps(&a, &b, 5);
        assert!(overlaps.is_empty());
    }

    #[test]
    fn file_overlap_with_self_returns_all_changed_files() {
        let a = make_changeset(vec![
            make_file("src/a.ts", vec![]),
            make_file("src/unicode/核心.ts", vec![]),
            make_file("src/space name.ts", vec![]),
        ]);

        let overlaps = compute_file_overlaps(&a, &a);
        assert_eq!(overlaps.len(), a.changed_files.len());
    }

    #[test]
    fn hunk_overlap_is_commutative() {
        let a = make_changeset(vec![make_file(
            "src/shared.ts",
            vec![
                Hunk {
                    old_start: 0,
                    old_lines: 0,
                    new_start: 0,
                    new_lines: 0,
                },
                Hunk {
                    old_start: 10,
                    old_lines: 3,
                    new_start: 10,
                    new_lines: 3,
                },
            ],
        )]);
        let b = make_changeset(vec![make_file(
            "src/shared.ts",
            vec![
                Hunk {
                    old_start: 0,
                    old_lines: 0,
                    new_start: 0,
                    new_lines: 0,
                },
                Hunk {
                    old_start: 11,
                    old_lines: 2,
                    new_start: 11,
                    new_lines: 2,
                },
            ],
        )]);

        let left = compute_hunk_overlaps(&a, &b, 5);
        let right = compute_hunk_overlaps(&b, &a, 5);

        fn key(overlap: &Overlap) -> (PathBuf, u32, (u32, u32), (u32, u32)) {
            match overlap {
                Overlap::Hunk {
                    path,
                    a_range,
                    b_range,
                    distance,
                } => {
                    let mut ranges = [(a_range.start, a_range.end), (b_range.start, b_range.end)];
                    ranges.sort_by(|l, r| {
                        let by_start = l.0.cmp(&r.0);
                        if by_start == Ordering::Equal {
                            l.1.cmp(&r.1)
                        } else {
                            by_start
                        }
                    });
                    (path.clone(), *distance, ranges[0], ranges[1])
                }
                _ => panic!("expected hunk overlap"),
            }
        }

        let mut left_keys: Vec<_> = left.iter().map(key).collect();
        let mut right_keys: Vec<_> = right.iter().map(key).collect();
        left_keys.sort();
        right_keys.sort();
        assert_eq!(left_keys, right_keys);
    }

    #[test]
    fn zero_length_hunks_are_supported() {
        let a = make_changeset(vec![make_file(
            "src/zero.ts",
            vec![Hunk {
                old_start: 0,
                old_lines: 0,
                new_start: 0,
                new_lines: 0,
            }],
        )]);
        let b = make_changeset(vec![make_file(
            "src/zero.ts",
            vec![Hunk {
                old_start: 0,
                old_lines: 0,
                new_start: 0,
                new_lines: 0,
            }],
        )]);

        let overlaps = compute_hunk_overlaps(&a, &b, 0);
        assert_eq!(overlaps.len(), 1);
    }

    #[test]
    fn hundred_hunks_all_pairwise_overlaps_are_reported() {
        let hunks: Vec<Hunk> = (0..100)
            .map(|_| Hunk {
                old_start: 1,
                old_lines: 1,
                new_start: 1,
                new_lines: 100,
            })
            .collect();

        let a = make_changeset(vec![make_file("src/big.ts", hunks.clone())]);
        let b = make_changeset(vec![make_file("src/big.ts", hunks)]);

        let overlaps = compute_hunk_overlaps(&a, &b, 0);
        assert_eq!(overlaps.len(), 10_000);
    }

    #[test]
    fn file_overlap_is_commutative_as_path_change_set() {
        fn rank(change: ChangeType) -> u8 {
            match change {
                ChangeType::Added => 0,
                ChangeType::Modified => 1,
                ChangeType::Deleted => 2,
                ChangeType::Renamed => 3,
            }
        }

        fn key(overlap: &Overlap) -> (PathBuf, u8, u8) {
            match overlap {
                Overlap::File {
                    path,
                    a_change,
                    b_change,
                } => {
                    let left = rank(*a_change);
                    let right = rank(*b_change);
                    (path.clone(), left.min(right), left.max(right))
                }
                _ => panic!("expected file overlap"),
            }
        }

        let mut a_one = make_file("src/shared_a.ts", vec![]);
        a_one.change_type = ChangeType::Added;
        let mut a_two = make_file("src/深い/层/feature.ts", vec![]);
        a_two.change_type = ChangeType::Deleted;

        let mut b_one = make_file("src/shared_a.ts", vec![]);
        b_one.change_type = ChangeType::Renamed;
        let mut b_two = make_file("src/深い/层/feature.ts", vec![]);
        b_two.change_type = ChangeType::Modified;

        let a = make_changeset(vec![a_one, a_two]);
        let b = make_changeset(vec![b_one, b_two]);

        let mut left: Vec<_> = compute_file_overlaps(&a, &b).iter().map(key).collect();
        let mut right: Vec<_> = compute_file_overlaps(&b, &a).iter().map(key).collect();
        left.sort();
        right.sort();

        assert_eq!(left, right);
        assert_eq!(left.len(), 2);
    }

    #[test]
    fn hunk_overlap_threshold_is_monotonic() {
        fn key(overlap: &Overlap) -> (PathBuf, (u32, u32), (u32, u32), u32) {
            match overlap {
                Overlap::Hunk {
                    path,
                    a_range,
                    b_range,
                    distance,
                } => (
                    path.clone(),
                    (a_range.start, a_range.end),
                    (b_range.start, b_range.end),
                    *distance,
                ),
                _ => panic!("expected hunk overlap"),
            }
        }

        let a = make_changeset(vec![make_file(
            "src/monotonic.ts",
            vec![
                Hunk {
                    old_start: 1,
                    old_lines: 1,
                    new_start: 1,
                    new_lines: 3,
                },
                Hunk {
                    old_start: 20,
                    old_lines: 1,
                    new_start: 20,
                    new_lines: 2,
                },
            ],
        )]);
        let b = make_changeset(vec![make_file(
            "src/monotonic.ts",
            vec![
                Hunk {
                    old_start: 6,
                    old_lines: 1,
                    new_start: 6,
                    new_lines: 2,
                },
                Hunk {
                    old_start: 24,
                    old_lines: 1,
                    new_start: 24,
                    new_lines: 2,
                },
            ],
        )]);

        let small = compute_hunk_overlaps(&a, &b, 1);
        let large = compute_hunk_overlaps(&a, &b, 6);

        let small_keys: std::collections::HashSet<_> = small.iter().map(key).collect();
        let large_keys: std::collections::HashSet<_> = large.iter().map(key).collect();

        assert!(small_keys.is_subset(&large_keys));
        assert!(large_keys.len() >= small_keys.len());
    }

    #[test]
    fn hunk_overlap_handles_very_deep_unicode_path() {
        let deep = (0..60)
            .map(|i| format!("层{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let path = format!("src/{deep}/核心.ts");

        let a = make_changeset(vec![make_file(
            &path,
            vec![Hunk {
                old_start: 10,
                old_lines: 1,
                new_start: 10,
                new_lines: 5,
            }],
        )]);
        let b = make_changeset(vec![make_file(
            &path,
            vec![Hunk {
                old_start: 12,
                old_lines: 1,
                new_start: 12,
                new_lines: 3,
            }],
        )]);

        let overlaps = compute_hunk_overlaps(&a, &b, 0);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Hunk {
                path: p, distance, ..
            } => {
                assert_eq!(p, &PathBuf::from(path));
                assert_eq!(*distance, 0);
            }
            _ => panic!("expected hunk overlap"),
        }
    }

    #[test]
    fn large_sparse_dataset_has_expected_overlap_counts() {
        let hunks_a: Vec<Hunk> = (0..120)
            .map(|i| Hunk {
                old_start: i * 10 + 1,
                old_lines: 1,
                new_start: i * 10 + 1,
                new_lines: 2,
            })
            .collect();
        let hunks_b: Vec<Hunk> = (0..120)
            .map(|i| Hunk {
                old_start: i * 10 + 5,
                old_lines: 1,
                new_start: i * 10 + 5,
                new_lines: 2,
            })
            .collect();

        let a = make_changeset(vec![make_file("src/large.ts", hunks_a)]);
        let b = make_changeset(vec![make_file("src/large.ts", hunks_b)]);

        let none = compute_hunk_overlaps(&a, &b, 2);
        let exact = compute_hunk_overlaps(&a, &b, 3);

        assert!(none.is_empty());
        assert_eq!(exact.len(), 120);
    }

    #[test]
    fn non_shared_files_do_not_produce_hunk_overlaps_under_load() {
        let mut a_files = Vec::new();
        let mut b_files = Vec::new();
        for i in 0..150 {
            a_files.push(make_file(
                &format!("src/a/file_{i}.ts"),
                vec![Hunk {
                    old_start: 1,
                    old_lines: 1,
                    new_start: i + 1,
                    new_lines: 1,
                }],
            ));
            b_files.push(make_file(
                &format!("src/b/file_{i}.ts"),
                vec![Hunk {
                    old_start: 1,
                    old_lines: 1,
                    new_start: i + 1,
                    new_lines: 1,
                }],
            ));
        }

        a_files.push(make_file(
            "src/shared.ts",
            vec![Hunk {
                old_start: 10,
                old_lines: 1,
                new_start: 10,
                new_lines: 1,
            }],
        ));
        b_files.push(make_file(
            "src/shared.ts",
            vec![Hunk {
                old_start: 10,
                old_lines: 1,
                new_start: 10,
                new_lines: 1,
            }],
        ));

        let a = make_changeset(a_files);
        let b = make_changeset(b_files);

        let overlaps = compute_hunk_overlaps(&a, &b, 0);
        assert_eq!(overlaps.len(), 1);
    }
}
