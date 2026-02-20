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
