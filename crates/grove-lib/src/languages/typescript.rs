use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

pub struct TypeScriptAnalyzer {
    parser_ts: std::sync::Mutex<Parser>,
    parser_tsx: std::sync::Mutex<Parser>,
}

impl Default for TypeScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser_ts = Parser::new();
        parser_ts
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to set typescript language");

        let mut parser_tsx = Parser::new();
        parser_tsx
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .expect("failed to set tsx language");

        Self {
            parser_ts: std::sync::Mutex::new(parser_ts),
            parser_tsx: std::sync::Mutex::new(parser_tsx),
        }
    }

    fn parse(&self, source: &[u8], is_tsx: bool) -> Result<tree_sitter::Tree, AnalysisError> {
        let mut parser = if is_tsx {
            self.parser_tsx.lock().unwrap()
        } else {
            self.parser_ts.lock().unwrap()
        };
        parser
            .parse(source, None)
            .ok_or_else(|| AnalysisError::ParseError("tree-sitter parse failed".into()))
    }
}

impl LanguageAnalyzer for TypeScriptAnalyzer {
    fn language_id(&self) -> &str {
        "typescript"
    }

    fn file_extensions(&self) -> &[&str] {
        &["ts", "tsx", "js", "jsx", "mts", "mjs"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            match child.kind() {
                "function_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Function,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: Some(
                                get_first_line(source, child.start_byte(), child.end_byte()),
                            ),
                        });
                    }
                }
                "class_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Class,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "interface_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Interface,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "type_alias_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::TypeAlias,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "enum_declaration" => {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.utf8_text(source).unwrap_or("").to_string();
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Enum,
                            range: LineRange {
                                start: child.start_position().row as u32 + 1,
                                end: child.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    // const/let/var declarations
                    let mut decl_cursor = child.walk();
                    for decl_child in child.children(&mut decl_cursor) {
                        if decl_child.kind() == "variable_declarator"
                            && let Some(name_node) = decl_child.child_by_field_name("name")
                        {
                            let name =
                                name_node.utf8_text(source).unwrap_or("").to_string();
                            symbols.push(Symbol {
                                name,
                                kind: SymbolKind::Variable,
                                range: LineRange {
                                    start: child.start_position().row as u32 + 1,
                                    end: child.end_position().row as u32 + 1,
                                },
                                signature: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "import_statement" {
                let line = child.start_position().row as u32 + 1;
                let mut source_path = String::new();
                let mut symbols = Vec::new();

                let mut import_cursor = child.walk();
                for import_child in child.children(&mut import_cursor) {
                    match import_child.kind() {
                        "string" | "template_string" => {
                            let raw = import_child.utf8_text(source).unwrap_or("");
                            // Strip quotes
                            source_path = raw.trim_matches(|c| c == '\'' || c == '"').to_string();
                        }
                        "import_clause" => {
                            let mut clause_cursor = import_child.walk();
                            for clause_child in import_child.children(&mut clause_cursor) {
                                if clause_child.kind() == "named_imports" {
                                    let mut named_cursor = clause_child.walk();
                                    for named_child in clause_child.children(&mut named_cursor) {
                                        if named_child.kind() == "import_specifier" {
                                            let name = named_child
                                                .child_by_field_name("name")
                                                .map(|n| {
                                                    n.utf8_text(source)
                                                        .unwrap_or("")
                                                        .to_string()
                                                })
                                                .unwrap_or_default();
                                            let alias = named_child
                                                .child_by_field_name("alias")
                                                .map(|n| {
                                                    n.utf8_text(source)
                                                        .unwrap_or("")
                                                        .to_string()
                                                });
                                            if !name.is_empty() {
                                                symbols.push(ImportedSymbol { name, alias });
                                            }
                                        }
                                    }
                                }
                                if clause_child.kind() == "identifier" {
                                    // Default import
                                    let name = clause_child
                                        .utf8_text(source)
                                        .unwrap_or("")
                                        .to_string();
                                    if !name.is_empty() {
                                        symbols.push(ImportedSymbol {
                                            name: "default".to_string(),
                                            alias: Some(name),
                                        });
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                if !source_path.is_empty() {
                    imports.push(Import {
                        source: source_path,
                        symbols,
                        line,
                    });
                }
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "export_statement" {
                let mut export_cursor = child.walk();
                for export_child in child.children(&mut export_cursor) {
                    match export_child.kind() {
                        "function_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::Function,
                                    signature: Some(get_first_line(
                                        source,
                                        export_child.start_byte(),
                                        export_child.end_byte(),
                                    )),
                                });
                            }
                        }
                        "class_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::Class,
                                    signature: None,
                                });
                            }
                        }
                        "interface_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::Interface,
                                    signature: None,
                                });
                            }
                        }
                        "type_alias_declaration" => {
                            if let Some(name_node) = export_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                    kind: SymbolKind::TypeAlias,
                                    signature: None,
                                });
                            }
                        }
                        _ => {}
                    }
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

        matches!(
            filename.as_str(),
            "package.json" | "tsconfig.json" | "next.config.js" | "next.config.ts"
                | "vite.config.ts" | "webpack.config.js"
        )
    }
}

fn get_first_line(source: &[u8], start: usize, end: usize) -> String {
    let slice = &source[start..end.min(source.len())];
    let text = String::from_utf8_lossy(slice);
    text.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_function_symbols() {
        let source = br#"
function processPayment(amount: number): boolean {
    return true;
}

function validateUser(id: string): User {
    return {} as User;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "processPayment");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert_eq!(symbols[1].name, "validateUser");
    }

    #[test]
    fn extracts_class_and_interface() {
        let source = br#"
class PaymentService {
    process() {}
}

interface PaymentConfig {
    amount: number;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "PaymentService");
        assert_eq!(symbols[0].kind, SymbolKind::Class);
        assert_eq!(symbols[1].name, "PaymentConfig");
        assert_eq!(symbols[1].kind, SymbolKind::Interface);
    }

    #[test]
    fn extracts_named_imports() {
        let source = br#"
import { processPayment, PaymentConfig } from './payment';
import { validateUser } from '../auth';
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "./payment");
        assert_eq!(imports[0].symbols.len(), 2);
        assert_eq!(imports[0].symbols[0].name, "processPayment");
        assert_eq!(imports[0].symbols[1].name, "PaymentConfig");
        assert_eq!(imports[1].source, "../auth");
    }

    #[test]
    fn extracts_exported_functions() {
        let source = br#"
export function processPayment(amount: number): boolean {
    return true;
}

export interface PaymentResult {
    success: boolean;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "processPayment");
        assert_eq!(exports[0].kind, SymbolKind::Function);
        assert_eq!(exports[1].name, "PaymentResult");
        assert_eq!(exports[1].kind, SymbolKind::Interface);
    }
}
