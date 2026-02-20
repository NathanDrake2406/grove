use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

pub struct RustAnalyzer {
    parser: std::sync::Mutex<Parser>,
}

impl Default for RustAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RustAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("failed to set rust language");
        Self {
            parser: std::sync::Mutex::new(parser),
        }
    }
}

impl LanguageAnalyzer for RustAnalyzer {
    fn language_id(&self) -> &str {
        "rust"
    }

    fn file_extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            match child.kind() {
                "function_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Function,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: Some(get_signature_line(source, child.start_byte())),
                        });
                    }
                }
                "struct_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Struct,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "enum_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Enum,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "trait_item" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Trait,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "impl_item" => {
                    if let Some(name_node) = child.child_by_field_name("type") {
                        symbols.push(Symbol {
                            name: name_node.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Impl,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "use_declaration" {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                let line = child.start_position().row as u32 + 1;
                // Extract the module path from "use crate::module::symbol;"
                let path = text
                    .trim_start_matches("use ")
                    .trim_end_matches(';')
                    .to_string();
                imports.push(Import {
                    source: path,
                    symbols: vec![], // TODO: parse use tree for individual symbols
                    line,
                });
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        // In Rust, "pub" items are exports. Check for pub visibility.
        let mut parser = self.parser.lock().unwrap();
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            // Check if the item has a visibility_modifier child with "pub"
            let is_pub = child
                .children(&mut child.walk())
                .any(|c| c.kind() == "visibility_modifier");

            if is_pub {
                match child.kind() {
                    "function_item" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            exports.push(ExportedSymbol {
                                name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                kind: SymbolKind::Function,
                                signature: Some(get_signature_line(source, child.start_byte())),
                            });
                        }
                    }
                    "struct_item" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            exports.push(ExportedSymbol {
                                name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                kind: SymbolKind::Struct,
                                signature: None,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(exports)
    }

    fn is_schema_file(&self, path: &Path) -> bool {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        matches!(filename.as_str(), "Cargo.toml" | "build.rs")
    }
}

fn get_signature_line(source: &[u8], start: usize) -> String {
    let slice = &source[start..];
    let text = String::from_utf8_lossy(slice);
    text.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_rust_function_symbols() {
        let source = br#"
fn process_payment(amount: u64) -> bool {
    true
}

pub fn validate_user(id: &str) -> User {
    todo!()
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "process_payment");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert_eq!(symbols[1].name, "validate_user");
    }

    #[test]
    fn extracts_rust_pub_exports() {
        let source = br#"
pub fn exported_fn() {}

fn private_fn() {}

pub struct ExportedStruct {
    pub field: i32,
}
"#;
        let analyzer = RustAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "exported_fn");
        assert_eq!(exports[1].name, "ExportedStruct");
    }

    #[test]
    fn extracts_rust_use_imports() {
        let source = br#"
use crate::types::Workspace;
use std::collections::HashMap;
"#;
        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 2);
        assert!(imports[0].source.contains("crate::types::Workspace"));
        assert!(imports[1].source.contains("std::collections::HashMap"));
    }
}
