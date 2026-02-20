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
    _a_overlay: &GraphOverlay,
    _b_overlay: &GraphOverlay,
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
