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
