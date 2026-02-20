use crate::types::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

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

/// Compute dependency-level overlaps between two workspace changesets.
/// This is the most expensive layer: it traces export signature changes
/// through the import graph to find affected files in the other workspace.
pub fn compute_dependency_overlaps(
    a_changeset: &WorkspaceChangeset,
    b_changeset: &WorkspaceChangeset,
    base_graph: &ImportGraph,
) -> Vec<Overlap> {
    let mut overlaps = Vec::new();
    let mut emitted_overlap_keys: HashSet<(WorkspaceId, PathBuf, usize, PathBuf)> = HashSet::new();

    let b_changed_files: HashSet<&Path> = b_changeset
        .changed_files
        .iter()
        .map(|f| f.path.as_path())
        .collect();
    collect_directional_dependency_overlaps(
        a_changeset,
        &b_changed_files,
        base_graph,
        &mut emitted_overlap_keys,
        &mut overlaps,
    );

    let a_changed_files: HashSet<&Path> = a_changeset
        .changed_files
        .iter()
        .map(|f| f.path.as_path())
        .collect();
    collect_directional_dependency_overlaps(
        b_changeset,
        &a_changed_files,
        base_graph,
        &mut emitted_overlap_keys,
        &mut overlaps,
    );

    overlaps
}

fn collect_directional_dependency_overlaps(
    source_changeset: &WorkspaceChangeset,
    target_changed_files: &HashSet<&Path>,
    base_graph: &ImportGraph,
    emitted_overlap_keys: &mut HashSet<(WorkspaceId, PathBuf, usize, PathBuf)>,
    overlaps: &mut Vec<Overlap>,
) {
    for changed_file in &source_changeset.changed_files {
        if changed_file.exports_changed.is_empty() {
            continue;
        }

        let transitive_dependents =
            collect_transitive_dependents(changed_file.path.as_path(), base_graph);

        for (export_delta_idx, export_delta) in changed_file.exports_changed.iter().enumerate() {
            for dependent_file in &transitive_dependents {
                if !target_changed_files.contains(dependent_file.as_path()) {
                    continue;
                }

                let overlap_key = (
                    source_changeset.workspace_id,
                    changed_file.path.clone(),
                    export_delta_idx,
                    dependent_file.clone(),
                );

                if !emitted_overlap_keys.insert(overlap_key) {
                    continue;
                }

                overlaps.push(Overlap::Dependency {
                    changed_in: source_changeset.workspace_id,
                    changed_file: changed_file.path.clone(),
                    changed_export: export_delta.clone(),
                    affected_file: dependent_file.clone(),
                    affected_usage: vec![],
                });
            }
        }
    }
}

fn collect_transitive_dependents(file: &Path, base_graph: &ImportGraph) -> Vec<PathBuf> {
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    let mut discovered = Vec::new();

    visited.insert(file.to_path_buf());
    queue.push_back(file.to_path_buf());

    while let Some(current) = queue.pop_front() {
        if let Some(direct_dependents) = base_graph.dependents.get(&current) {
            for (dependent_file, _) in direct_dependents {
                if !visited.insert(dependent_file.clone()) {
                    continue;
                }

                discovered.push(dependent_file.clone());
                queue.push_back(dependent_file.clone());
            }
        }
    }

    discovered
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
            vec![ImportedSymbol {
                name: "authenticate".into(),
                alias: None,
            }],
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
            vec![ImportedSymbol {
                name: "authenticate".into(),
                alias: None,
            }],
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
                    old: Signature {
                        text: "fn authenticate() -> bool".into(),
                    },
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

        let overlaps = compute_dependency_overlaps(&a, &b, &base_graph);

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
            vec![ImportedSymbol {
                name: "authenticate".into(),
                alias: None,
            }],
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

        let overlaps = compute_dependency_overlaps(&a, &b, &base_graph);

        assert!(overlaps.is_empty());
    }

    #[test]
    fn empty_overlay_preserves_base_exports() {
        let mut base_graph = ImportGraph::new();
        let file = PathBuf::from("src/lib.ts");
        let expected = vec![ExportedSymbol {
            name: "run".to_string(),
            kind: SymbolKind::Function,
            signature: Some("export function run()".to_string()),
        }];
        base_graph.set_exports(file.clone(), expected.clone());

        let overlay = GraphOverlay::new();
        let effective = overlay.effective_exports(&file, &base_graph).unwrap();
        assert_eq!(effective, &expected);
    }

    #[test]
    fn modified_exports_override_base_graph_exports() {
        let mut base_graph = ImportGraph::new();
        let file = PathBuf::from("src/lib.ts");
        base_graph.set_exports(
            file.clone(),
            vec![ExportedSymbol {
                name: "old".to_string(),
                kind: SymbolKind::Function,
                signature: None,
            }],
        );

        let mut overlay = GraphOverlay::new();
        overlay.modified_exports.insert(
            file.clone(),
            vec![ExportedSymbol {
                name: "new".to_string(),
                kind: SymbolKind::Function,
                signature: None,
            }],
        );

        let effective = overlay.effective_exports(&file, &base_graph).unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].name, "new");
    }

    #[test]
    fn dependency_overlap_traces_transitive_dependents() {
        let mut base_graph = ImportGraph::new();
        // A <- B <- C <- D (D depends on C, C depends on B, B depends on A)
        base_graph.add_import(
            PathBuf::from("B.ts"),
            PathBuf::from("A.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            PathBuf::from("C.ts"),
            PathBuf::from("B.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            PathBuf::from("D.ts"),
            PathBuf::from("C.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );

        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();
        let a_changeset = WorkspaceChangeset {
            workspace_id: a_id,
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("A.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![ExportDelta::Added(Symbol {
                    name: "x".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 1 },
                    signature: None,
                })],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let b_changeset = WorkspaceChangeset {
            workspace_id: b_id,
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("D.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_dependency_overlaps(&a_changeset, &b_changeset, &base_graph);

        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Dependency {
                changed_in,
                changed_file,
                affected_file,
                ..
            } => {
                assert_eq!(*changed_in, a_id);
                assert_eq!(changed_file, &PathBuf::from("A.ts"));
                assert_eq!(affected_file, &PathBuf::from("D.ts"));
            }
            _ => panic!("expected dependency overlap"),
        }
    }

    #[test]
    fn overlay_removed_file_masks_modified_and_added_exports() {
        let mut base_graph = ImportGraph::new();
        let file = PathBuf::from("src/feature.ts");
        base_graph.set_exports(
            file.clone(),
            vec![ExportedSymbol {
                name: "baseExport".to_string(),
                kind: SymbolKind::Function,
                signature: None,
            }],
        );

        let mut overlay = GraphOverlay::new();
        overlay.modified_exports.insert(
            file.clone(),
            vec![ExportedSymbol {
                name: "modifiedExport".to_string(),
                kind: SymbolKind::Function,
                signature: None,
            }],
        );
        overlay.added_files.insert(
            file.clone(),
            (
                vec![],
                vec![ExportedSymbol {
                    name: "addedExport".to_string(),
                    kind: SymbolKind::Function,
                    signature: None,
                }],
            ),
        );
        overlay.removed_files.insert(file.clone());

        assert!(overlay.has_export_changes(&file));
        assert!(overlay.effective_exports(&file, &base_graph).is_none());
    }

    #[test]
    fn overlay_prefers_modified_exports_over_added_and_base() {
        let mut base_graph = ImportGraph::new();
        let file = PathBuf::from("src/lib.ts");
        base_graph.set_exports(
            file.clone(),
            vec![ExportedSymbol {
                name: "base".to_string(),
                kind: SymbolKind::Function,
                signature: None,
            }],
        );

        let mut overlay = GraphOverlay::new();
        overlay.added_files.insert(
            file.clone(),
            (
                vec![],
                vec![ExportedSymbol {
                    name: "added".to_string(),
                    kind: SymbolKind::Function,
                    signature: None,
                }],
            ),
        );
        overlay.modified_exports.insert(
            file.clone(),
            vec![ExportedSymbol {
                name: "modified".to_string(),
                kind: SymbolKind::Function,
                signature: None,
            }],
        );

        let effective = overlay.effective_exports(&file, &base_graph).unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].name, "modified");
    }

    #[test]
    fn dependency_overlap_multiplies_export_deltas_by_dependents() {
        let mut base_graph = ImportGraph::new();
        let api = PathBuf::from("src/api.ts");
        let consumer_a = PathBuf::from("src/consumer_a.ts");
        let consumer_b = PathBuf::from("src/consumer_b.ts");

        base_graph.add_import(
            consumer_a.clone(),
            api.clone(),
            vec![ImportedSymbol {
                name: "foo".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            consumer_b.clone(),
            api.clone(),
            vec![ImportedSymbol {
                name: "bar".into(),
                alias: None,
            }],
        );

        let a_id = Uuid::new_v4();
        let a = WorkspaceChangeset {
            workspace_id: a_id,
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: api.clone(),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![
                    ExportDelta::SignatureChanged {
                        symbol_name: "foo".into(),
                        old: Signature {
                            text: "fn foo()".into(),
                        },
                        new: Signature {
                            text: "fn foo(v: i32)".into(),
                        },
                    },
                    ExportDelta::SignatureChanged {
                        symbol_name: "bar".into(),
                        old: Signature {
                            text: "fn bar()".into(),
                        },
                        new: Signature {
                            text: "fn bar(v: i32)".into(),
                        },
                    },
                ],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let b = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![
                FileChange {
                    path: consumer_a.clone(),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                },
                FileChange {
                    path: consumer_b.clone(),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                },
            ],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_dependency_overlaps(&a, &b, &base_graph);

        assert_eq!(overlaps.len(), 4);
        let mut affected = std::collections::HashSet::new();
        for overlap in overlaps {
            match overlap {
                Overlap::Dependency {
                    changed_in,
                    changed_file,
                    affected_file,
                    ..
                } => {
                    assert_eq!(changed_in, a_id);
                    assert_eq!(changed_file, api);
                    affected.insert(affected_file);
                }
                _ => panic!("expected dependency overlap"),
            }
        }
        assert_eq!(affected.len(), 2);
        assert!(affected.contains(&consumer_a));
        assert!(affected.contains(&consumer_b));
    }

    #[test]
    fn dependency_overlap_reports_both_directions_when_each_side_breaks_other() {
        let mut base_graph = ImportGraph::new();

        base_graph.add_import(
            PathBuf::from("src/router.ts"),
            PathBuf::from("src/auth.ts"),
            vec![ImportedSymbol {
                name: "authenticate".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            PathBuf::from("src/billing.ts"),
            PathBuf::from("src/pricing.ts"),
            vec![ImportedSymbol {
                name: "quote".into(),
                alias: None,
            }],
        );

        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();
        let a = WorkspaceChangeset {
            workspace_id: a_id,
            merge_base: "abc".into(),
            changed_files: vec![
                FileChange {
                    path: PathBuf::from("src/auth.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![ExportDelta::Added(Symbol {
                        name: "authenticate".into(),
                        kind: SymbolKind::Function,
                        range: LineRange { start: 1, end: 1 },
                        signature: None,
                    })],
                },
                FileChange {
                    path: PathBuf::from("src/billing.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                },
            ],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let b = WorkspaceChangeset {
            workspace_id: b_id,
            merge_base: "abc".into(),
            changed_files: vec![
                FileChange {
                    path: PathBuf::from("src/pricing.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![ExportDelta::Added(Symbol {
                        name: "quote".into(),
                        kind: SymbolKind::Function,
                        range: LineRange { start: 1, end: 1 },
                        signature: None,
                    })],
                },
                FileChange {
                    path: PathBuf::from("src/router.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                },
            ],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_dependency_overlaps(&a, &b, &base_graph);
        assert_eq!(overlaps.len(), 2);

        let changed_in: std::collections::HashSet<_> = overlaps
            .into_iter()
            .map(|o| match o {
                Overlap::Dependency { changed_in, .. } => changed_in,
                _ => panic!("expected dependency overlap"),
            })
            .collect();
        assert!(changed_in.contains(&a_id));
        assert!(changed_in.contains(&b_id));
    }

    #[test]
    fn dependency_overlap_propagates_transitively_but_not_to_unrelated_large_change_sets() {
        let mut base_graph = ImportGraph::new();
        // mid depends on api, leaf depends on mid (transitive-only w.r.t. api)
        base_graph.add_import(
            PathBuf::from("src/mid.ts"),
            PathBuf::from("src/api.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            PathBuf::from("src/leaf.ts"),
            PathBuf::from("src/mid.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );

        let a = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("src/api.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![ExportDelta::Added(Symbol {
                    name: "x".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 1 },
                    signature: None,
                })],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let mut b_files = Vec::new();
        b_files.push(FileChange {
            path: PathBuf::from("src/leaf.ts"),
            change_type: ChangeType::Modified,
            hunks: vec![],
            symbols_modified: vec![],
            exports_changed: vec![],
        });
        for i in 0..100 {
            b_files.push(FileChange {
                path: PathBuf::from(format!("src/unrelated_{i}.ts")),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            });
        }

        let b = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: b_files,
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_dependency_overlaps(&a, &b, &base_graph);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Dependency {
                changed_file,
                affected_file,
                ..
            } => {
                assert_eq!(changed_file, &PathBuf::from("src/api.ts"));
                assert_eq!(affected_file, &PathBuf::from("src/leaf.ts"));
            }
            _ => panic!("expected dependency overlap"),
        }
    }

    #[test]
    fn dependency_overlap_transitive_traversal_is_cycle_safe_and_deduplicated() {
        let mut base_graph = ImportGraph::new();
        base_graph.add_import(
            PathBuf::from("B.ts"),
            PathBuf::from("A.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            PathBuf::from("C.ts"),
            PathBuf::from("B.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );
        base_graph.add_import(
            PathBuf::from("A.ts"),
            PathBuf::from("C.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );
        // Duplicate edge to confirm we don't emit duplicate overlaps.
        base_graph.add_import(
            PathBuf::from("B.ts"),
            PathBuf::from("A.ts"),
            vec![ImportedSymbol {
                name: "x".into(),
                alias: None,
            }],
        );

        let a = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("A.ts"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![ExportDelta::Added(Symbol {
                    name: "x".into(),
                    kind: SymbolKind::Function,
                    range: LineRange { start: 1, end: 1 },
                    signature: None,
                })],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let b = WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![
                FileChange {
                    path: PathBuf::from("B.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                },
                FileChange {
                    path: PathBuf::from("C.ts"),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                },
            ],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_dependency_overlaps(&a, &b, &base_graph);

        assert_eq!(overlaps.len(), 2);
        let affected_files: HashSet<_> = overlaps
            .into_iter()
            .map(|overlap| match overlap {
                Overlap::Dependency { affected_file, .. } => affected_file,
                _ => panic!("expected dependency overlap"),
            })
            .collect();
        assert!(affected_files.contains(&PathBuf::from("B.ts")));
        assert!(affected_files.contains(&PathBuf::from("C.ts")));
    }
}
