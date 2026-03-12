use crate::languages::LanguageRegistry;
use crate::{
    ChangeType, CommitHash, ExportDelta, ExportedSymbol, FileChange, Hunk, LineRange, Signature,
    Symbol, WorkspaceChangeset, WorkspaceId,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentChange {
    pub path: PathBuf,
    pub old_path: Option<PathBuf>,
    pub change_type: ChangeType,
    pub old_content: Option<Vec<u8>>,
    pub new_content: Option<Vec<u8>>,
}

pub fn build_workspace_changeset(
    registry: &LanguageRegistry,
    workspace_id: WorkspaceId,
    merge_base: CommitHash,
    commits_ahead: u32,
    commits_behind: u32,
    changes: Vec<ContentChange>,
    max_file_size_bytes: u64,
) -> WorkspaceChangeset {
    let changed_files = changes
        .into_iter()
        .map(|change| {
            let old_path = change.old_path.as_deref().unwrap_or(change.path.as_path());
            let hunks = compute_hunks_from_content(
                change.old_content.as_deref(),
                change.new_content.as_deref(),
            );
            let symbols_modified = extract_modified_symbols(
                registry,
                change.path.as_path(),
                change.new_content.as_deref(),
                &hunks,
                change.change_type,
                max_file_size_bytes,
            );
            let old_exports = extract_exports(
                registry,
                old_path,
                change.old_content.as_deref(),
                max_file_size_bytes,
            );
            let new_exports = extract_exports(
                registry,
                change.path.as_path(),
                change.new_content.as_deref(),
                max_file_size_bytes,
            );

            FileChange {
                path: change.path,
                change_type: change.change_type,
                hunks,
                symbols_modified,
                exports_changed: compute_export_deltas(&old_exports, &new_exports),
            }
        })
        .collect();

    WorkspaceChangeset {
        workspace_id,
        merge_base,
        changed_files,
        commits_ahead,
        commits_behind,
    }
}

/// Equivalent to `git diff --unified=0`, computed from in-memory content.
pub fn compute_hunks_from_content(old: Option<&[u8]>, new: Option<&[u8]>) -> Vec<Hunk> {
    let old_str = old.map(String::from_utf8_lossy).unwrap_or_default();
    let new_str = new.map(String::from_utf8_lossy).unwrap_or_default();

    let diff = similar::TextDiff::from_lines(old_str.as_ref(), new_str.as_ref());
    let groups = diff.grouped_ops(0);

    let mut hunks = Vec::new();
    for group in groups {
        let mut old_start = u32::MAX;
        let mut old_end = 0u32;
        let mut new_start = u32::MAX;
        let mut new_end = 0u32;

        for op in &group {
            let os = op.old_range().start as u32;
            let oe = op.old_range().end as u32;
            let ns = op.new_range().start as u32;
            let ne = op.new_range().end as u32;

            old_start = old_start.min(os + 1);
            old_end = old_end.max(oe);
            new_start = new_start.min(ns + 1);
            new_end = new_end.max(ne);
        }

        let old_lines = old_end.saturating_sub(old_start.saturating_sub(1));
        let new_lines = new_end.saturating_sub(new_start.saturating_sub(1));

        if old_start == u32::MAX {
            old_start = 0;
        }
        if new_start == u32::MAX {
            new_start = 0;
        }

        hunks.push(Hunk {
            old_start,
            old_lines,
            new_start,
            new_lines,
        });
    }

    hunks
}

fn extract_modified_symbols(
    registry: &LanguageRegistry,
    path: &Path,
    content: Option<&[u8]>,
    hunks: &[Hunk],
    change_type: ChangeType,
    max_file_size_bytes: u64,
) -> Vec<Symbol> {
    let Some(bytes) = content else {
        return Vec::new();
    };

    if bytes.len() as u64 > max_file_size_bytes {
        return Vec::new();
    }

    let Some(analyzer) = registry.analyzer_for_file(path) else {
        return Vec::new();
    };

    let symbols = match analyzer.extract_symbols(bytes) {
        Ok(symbols) => symbols,
        Err(_) => return Vec::new(),
    };

    match change_type {
        ChangeType::Added => symbols,
        ChangeType::Deleted => Vec::new(),
        ChangeType::Modified | ChangeType::Renamed => {
            if hunks.is_empty() {
                return Vec::new();
            }

            symbols
                .into_iter()
                .filter(|symbol| symbol_in_hunks(symbol, hunks))
                .collect()
        }
    }
}

fn symbol_in_hunks(symbol: &Symbol, hunks: &[Hunk]) -> bool {
    hunks.iter().any(|hunk| {
        let start = hunk.new_start;
        let end = if hunk.new_lines == 0 {
            hunk.new_start
        } else {
            hunk.new_start + hunk.new_lines.saturating_sub(1)
        };
        symbol.range.overlaps(&LineRange { start, end })
    })
}

fn extract_exports(
    registry: &LanguageRegistry,
    path: &Path,
    content: Option<&[u8]>,
    max_file_size_bytes: u64,
) -> Vec<ExportedSymbol> {
    let Some(bytes) = content else {
        return Vec::new();
    };

    if bytes.len() as u64 > max_file_size_bytes {
        return Vec::new();
    }

    let Some(analyzer) = registry.analyzer_for_file(path) else {
        return Vec::new();
    };

    analyzer.extract_exports(bytes).unwrap_or_default()
}

fn compute_export_deltas(
    old_exports: &[ExportedSymbol],
    new_exports: &[ExportedSymbol],
) -> Vec<ExportDelta> {
    let old_by_name: BTreeMap<&str, &ExportedSymbol> = old_exports
        .iter()
        .map(|exported| (exported.name.as_str(), exported))
        .collect();
    let new_by_name: BTreeMap<&str, &ExportedSymbol> = new_exports
        .iter()
        .map(|exported| (exported.name.as_str(), exported))
        .collect();

    let mut deltas = Vec::new();

    for (name, new_symbol) in &new_by_name {
        if let Some(old_symbol) = old_by_name.get(name) {
            if old_symbol.signature != new_symbol.signature || old_symbol.kind != new_symbol.kind {
                deltas.push(ExportDelta::SignatureChanged {
                    symbol_name: (*name).to_string(),
                    old: Signature {
                        text: signature_text(old_symbol),
                    },
                    new: Signature {
                        text: signature_text(new_symbol),
                    },
                });
            }
        } else {
            deltas.push(ExportDelta::Added(exported_to_symbol(new_symbol)));
        }
    }

    for (name, old_symbol) in &old_by_name {
        if !new_by_name.contains_key(name) {
            deltas.push(ExportDelta::Removed(exported_to_symbol(old_symbol)));
        }
    }

    deltas
}

fn signature_text(exported: &ExportedSymbol) -> String {
    exported
        .signature
        .clone()
        .unwrap_or_else(|| format!("{:?}:{}", exported.kind, exported.name))
}

fn exported_to_symbol(exported: &ExportedSymbol) -> Symbol {
    Symbol {
        name: exported.name.clone(),
        kind: exported.kind,
        range: LineRange { start: 0, end: 0 },
        signature: exported.signature.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SymbolKind;
    use crate::languages::LanguageRegistry;
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn compute_hunks_from_content_detects_insertions_and_modifications() {
        let hunks = compute_hunks_from_content(
            Some(b"fn alpha() {}\nfn beta() {}\n"),
            Some(b"fn alpha() {}\nfn beta(v: i32) {}\nfn gamma() {}\n"),
        );

        assert_eq!(hunks.len(), 1);
        assert_eq!(
            hunks[0],
            Hunk {
                old_start: 2,
                old_lines: 1,
                new_start: 2,
                new_lines: 2,
            }
        );
    }

    #[test]
    fn symbol_in_hunks_detects_overlap_and_respects_zero_length_hunks() {
        let symbol = Symbol {
            name: "handler".to_string(),
            kind: SymbolKind::Function,
            range: LineRange { start: 10, end: 14 },
            signature: None,
        };
        let overlaps = symbol_in_hunks(
            &symbol,
            &[Hunk {
                old_start: 0,
                old_lines: 0,
                new_start: 12,
                new_lines: 2,
            }],
        );
        assert!(overlaps);

        let no_overlap = symbol_in_hunks(
            &symbol,
            &[Hunk {
                old_start: 0,
                old_lines: 0,
                new_start: 25,
                new_lines: 0,
            }],
        );
        assert!(!no_overlap);
    }

    #[test]
    fn compute_export_deltas_reports_added_removed_and_signature_changes() {
        let old_exports = vec![
            ExportedSymbol {
                name: "keep".to_string(),
                kind: SymbolKind::Function,
                signature: Some("fn keep()".to_string()),
            },
            ExportedSymbol {
                name: "remove_me".to_string(),
                kind: SymbolKind::Function,
                signature: Some("fn remove_me()".to_string()),
            },
        ];
        let new_exports = vec![
            ExportedSymbol {
                name: "keep".to_string(),
                kind: SymbolKind::Function,
                signature: Some("fn keep(v: i32)".to_string()),
            },
            ExportedSymbol {
                name: "add_me".to_string(),
                kind: SymbolKind::Function,
                signature: Some("fn add_me()".to_string()),
            },
        ];

        let deltas = compute_export_deltas(&old_exports, &new_exports);
        assert!(
            deltas.iter().any(
                |delta| matches!(delta, ExportDelta::Added(symbol) if symbol.name == "add_me")
            )
        );
        assert!(deltas.iter().any(
            |delta| matches!(delta, ExportDelta::Removed(symbol) if symbol.name == "remove_me")
        ));
        assert!(deltas.iter().any(|delta| matches!(
            delta,
            ExportDelta::SignatureChanged { symbol_name, .. } if symbol_name == "keep"
        )));
    }

    #[test]
    fn signature_text_falls_back_when_signature_is_missing() {
        let exported = ExportedSymbol {
            name: "Count".to_string(),
            kind: SymbolKind::Struct,
            signature: None,
        };

        let text = signature_text(&exported);
        assert!(text.contains("Struct"));
        assert!(text.contains("Count"));
    }

    #[test]
    fn extract_modified_symbols_handles_added_deleted_and_modified_cases() {
        let registry = LanguageRegistry::with_defaults();
        let content = br#"fn alpha() {}
fn beta() {}
"#;

        let added = extract_modified_symbols(
            &registry,
            Path::new("src/lib.rs"),
            Some(content),
            &[],
            ChangeType::Added,
            1024 * 1024,
        );
        assert!(!added.is_empty());

        let deleted = extract_modified_symbols(
            &registry,
            Path::new("src/lib.rs"),
            Some(content),
            &[],
            ChangeType::Deleted,
            1024 * 1024,
        );
        assert!(deleted.is_empty());

        let modified_without_hunks = extract_modified_symbols(
            &registry,
            Path::new("src/lib.rs"),
            Some(content),
            &[],
            ChangeType::Modified,
            1024 * 1024,
        );
        assert!(modified_without_hunks.is_empty());

        let modified_with_hunk = extract_modified_symbols(
            &registry,
            Path::new("src/lib.rs"),
            Some(content),
            &[Hunk {
                old_start: 1,
                old_lines: 1,
                new_start: 1,
                new_lines: 1,
            }],
            ChangeType::Modified,
            1024 * 1024,
        );
        assert!(!modified_with_hunk.is_empty());
    }

    #[test]
    fn extract_exports_returns_empty_for_unknown_or_oversized_files() {
        let registry = LanguageRegistry::with_defaults();
        let unknown = extract_exports(
            &registry,
            Path::new("assets/data.bin"),
            Some(b"binary"),
            1024,
        );
        assert!(unknown.is_empty());

        let oversized = extract_exports(
            &registry,
            Path::new("src/lib.rs"),
            Some(b"fn tiny() {}\n"),
            1,
        );
        assert!(oversized.is_empty());
    }

    #[test]
    fn build_workspace_changeset_uses_old_path_for_renamed_exports() {
        let registry = LanguageRegistry::with_defaults();
        let changeset = build_workspace_changeset(
            &registry,
            Uuid::new_v4(),
            "base123".to_string(),
            2,
            1,
            vec![ContentChange {
                path: PathBuf::from("src/new_name.rs"),
                old_path: Some(PathBuf::from("src/old_name.rs")),
                change_type: ChangeType::Renamed,
                old_content: Some(b"pub fn before() {}\n".to_vec()),
                new_content: Some(b"pub fn after() {}\n".to_vec()),
            }],
            1024 * 1024,
        );

        assert_eq!(changeset.commits_ahead, 2);
        assert_eq!(changeset.commits_behind, 1);
        assert_eq!(changeset.changed_files.len(), 1);
        assert!(
            changeset.changed_files[0].exports_changed.iter().any(
                |delta| matches!(delta, ExportDelta::Removed(symbol) if symbol.name == "before")
            )
        );
        assert!(
            changeset.changed_files[0]
                .exports_changed
                .iter()
                .any(|delta| matches!(delta, ExportDelta::Added(symbol) if symbol.name == "after"))
        );
    }
}
