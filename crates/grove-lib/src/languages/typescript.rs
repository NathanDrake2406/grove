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
        visit_descendants(root, &mut |node| match node.kind() {
            "function_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Function,
                        range: LineRange {
                            start: node.start_position().row as u32 + 1,
                            end: node.end_position().row as u32 + 1,
                        },
                        signature: Some(get_first_line(source, node.start_byte(), node.end_byte())),
                    });
                }
            }
            "method_definition" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    if !name.is_empty() {
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Method,
                            range: LineRange {
                                start: node.start_position().row as u32 + 1,
                                end: node.end_position().row as u32 + 1,
                            },
                            signature: Some(get_first_line(
                                source,
                                node.start_byte(),
                                node.end_byte(),
                            )),
                        });
                    }
                }
            }
            "class_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Class,
                        range: LineRange {
                            start: node.start_position().row as u32 + 1,
                            end: node.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
            "interface_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Interface,
                        range: LineRange {
                            start: node.start_position().row as u32 + 1,
                            end: node.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
            "type_alias_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::TypeAlias,
                        range: LineRange {
                            start: node.start_position().row as u32 + 1,
                            end: node.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
            "enum_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Enum,
                        range: LineRange {
                            start: node.start_position().row as u32 + 1,
                            end: node.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
            "variable_declarator" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let mut names = Vec::new();
                    collect_binding_identifiers(name_node, source, &mut names);
                    for name in names {
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Variable,
                            range: LineRange {
                                start: node.start_position().row as u32 + 1,
                                end: node.end_position().row as u32 + 1,
                            },
                            signature: None,
                        });
                    }
                }
            }
            _ => {}
        });

        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let tree = self.parse(source, false)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        visit_descendants(root, &mut |node| match node.kind() {
            "import_statement" => {
                if let Some(import) = extract_static_import(node, source) {
                    imports.push(import);
                }
            }
            "call_expression" => {
                if let Some(import) = extract_dynamic_import(node, source) {
                    imports.push(import);
                }
            }
            _ => {}
        });

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
                        "export_clause" => {
                            let mut clause_cursor = export_child.walk();
                            for clause_child in export_child.children(&mut clause_cursor) {
                                if clause_child.kind() == "export_specifier" {
                                    let alias = clause_child.child_by_field_name("alias");
                                    let name = clause_child.child_by_field_name("name");
                                    let exported_name = alias.or(name).and_then(|n| {
                                        let text = n.utf8_text(source).unwrap_or("").to_string();
                                        if text.is_empty() { None } else { Some(text) }
                                    });

                                    if let Some(name) = exported_name {
                                        exports.push(ExportedSymbol {
                                            name,
                                            kind: SymbolKind::Variable,
                                            signature: None,
                                        });
                                    }
                                }
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
            "package.json"
                | "tsconfig.json"
                | "next.config.js"
                | "next.config.ts"
                | "vite.config.ts"
                | "webpack.config.js"
        )
    }
}

fn get_first_line(source: &[u8], start: usize, end: usize) -> String {
    let slice = &source[start..end.min(source.len())];
    let text = String::from_utf8_lossy(slice);
    text.lines().next().unwrap_or("").to_string()
}

fn visit_descendants<'tree, F>(node: tree_sitter::Node<'tree>, f: &mut F)
where
    F: FnMut(tree_sitter::Node<'tree>),
{
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit_descendants(child, f);
    }
}

fn collect_binding_identifiers(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    names: &mut Vec<String>,
) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => {
            let name = node.utf8_text(source).unwrap_or("").to_string();
            if !name.is_empty() {
                names.push(name);
            }
        }
        _ => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_binding_identifiers(child, source, names);
            }
        }
    }
}

fn extract_static_import(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<Import> {
    let line = node.start_position().row as u32 + 1;
    let mut source_path = node
        .child_by_field_name("source")
        .and_then(|n| extract_string_value(n, source))
        .unwrap_or_default();
    let mut symbols = Vec::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string" | "template_string" if source_path.is_empty() => {
                source_path = extract_string_value(child, source).unwrap_or_default();
            }
            "import_clause" => {
                let mut clause_cursor = child.walk();
                for clause_child in child.children(&mut clause_cursor) {
                    match clause_child.kind() {
                        "identifier" => {
                            let name = clause_child.utf8_text(source).unwrap_or("").to_string();
                            if !name.is_empty() {
                                symbols.push(ImportedSymbol {
                                    name: "default".to_string(),
                                    alias: Some(name),
                                });
                            }
                        }
                        "named_imports" => {
                            let mut named_cursor = clause_child.walk();
                            for named_child in clause_child.children(&mut named_cursor) {
                                if named_child.kind() == "import_specifier" {
                                    let name = named_child
                                        .child_by_field_name("name")
                                        .map(|n| n.utf8_text(source).unwrap_or("").to_string())
                                        .unwrap_or_default();
                                    let alias = named_child
                                        .child_by_field_name("alias")
                                        .map(|n| n.utf8_text(source).unwrap_or("").to_string());

                                    if !name.is_empty() {
                                        symbols.push(ImportedSymbol { name, alias });
                                    }
                                }
                            }
                        }
                        "namespace_import" => {
                            let alias = clause_child
                                .child_by_field_name("name")
                                .or_else(|| {
                                    let mut ns_cursor = clause_child.walk();
                                    clause_child
                                        .children(&mut ns_cursor)
                                        .find(|n| n.kind() == "identifier")
                                })
                                .map(|n| n.utf8_text(source).unwrap_or("").to_string())
                                .filter(|s| !s.is_empty());

                            if let Some(alias) = alias {
                                symbols.push(ImportedSymbol {
                                    name: "*".to_string(),
                                    alias: Some(alias),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if source_path.is_empty() {
        None
    } else {
        Some(Import {
            source: source_path,
            symbols,
            line,
        })
    }
}

fn extract_dynamic_import(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<Import> {
    let function = node.child_by_field_name("function")?;
    if function.kind() != "import" {
        return None;
    }

    let arguments = node.child_by_field_name("arguments")?;
    let mut arg_cursor = arguments.walk();
    for argument in arguments.children(&mut arg_cursor) {
        if matches!(argument.kind(), "string" | "template_string")
            && let Some(source_path) = extract_string_value(argument, source)
        {
            return Some(Import {
                source: source_path,
                symbols: vec![],
                line: node.start_position().row as u32 + 1,
            });
        }
    }

    None
}

fn extract_string_value(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let raw = node.utf8_text(source).ok()?;
    let trimmed = raw.trim();
    let value = trimmed.trim_matches(|c| c == '\'' || c == '"' || c == '`');
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
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
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "PaymentService" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "PaymentConfig" && s.kind == SymbolKind::Interface)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "process" && s.kind == SymbolKind::Method)
        );
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

    #[test]
    fn complex_typescript_parsing_handles_nested_and_dynamic_constructs() {
        let source = br#"
class Outer {
    classField = 1;
    method() {
        class Inner {
            deep() {}
        }
        return new Inner();
    }
}

const { alpha, beta: renamed } = someObject;
export default class DefaultExported {}
export { renamed as reRenamed } from "./other";
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols.iter().any(|s| s.name == "Outer"));
        assert!(symbols.iter().any(|s| s.name == "alpha"));
        assert!(symbols.iter().any(|s| s.name == "renamed"));
        assert!(symbols.iter().any(|s| s.name == "method"));
        assert!(symbols.iter().any(|s| s.name == "Inner"));
    }

    #[test]
    fn extract_imports_supports_default_named_namespace_and_dynamic_imports() {
        let source = br#"
import React, { useMemo as memo } from "react";
import * as fs from "node:fs";
const mod = await import("./dynamic");
"#;

        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].source, "react");
        assert_eq!(imports[0].symbols[0].name, "default");
        assert_eq!(imports[0].symbols[0].alias.as_deref(), Some("React"));
        assert_eq!(imports[0].symbols[1].name, "useMemo");
        assert_eq!(imports[0].symbols[1].alias.as_deref(), Some("memo"));
        assert_eq!(imports[1].source, "node:fs");
        assert_eq!(imports[1].symbols.len(), 1);
        assert_eq!(imports[1].symbols[0].name, "*");
        assert_eq!(imports[1].symbols[0].alias.as_deref(), Some("fs"));
        assert_eq!(imports[2].source, "./dynamic");
    }

    #[test]
    fn extract_exports_handles_default_and_reexport_aliases() {
        let source = br#"
export default class DefaultThing {}
export { foo as bar } from "./foo";
export function named() {}
"#;

        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert!(exports.iter().any(|e| e.name == "DefaultThing"));
        assert!(exports.iter().any(|e| e.name == "named"));
        assert!(exports.iter().any(|e| e.name == "bar"));
    }

    #[test]
    fn schema_file_detection_handles_nested_paths_and_spaces() {
        let analyzer = TypeScriptAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("a/b/c with spaces/next.config.ts")));
        assert!(analyzer.is_schema_file(Path::new("deep/nested/project/tsconfig.json")));
    }

    #[test]
    fn malformed_source_recovers_and_keeps_earlier_symbols() {
        let source = br#"
function stableTopLevel() {}

type Broken<T = ;

function mayRecoverLater() {}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "stableTopLevel"));
    }

    #[test]
    fn import_alias_collisions_preserve_each_specifier() {
        let source = br#"
import { foo as value, bar as value, value as foo } from "./dep";
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "./dep");
        assert_eq!(imports[0].symbols.len(), 3);
        assert_eq!(imports[0].symbols[0].name, "foo");
        assert_eq!(imports[0].symbols[0].alias.as_deref(), Some("value"));
        assert_eq!(imports[0].symbols[1].name, "bar");
        assert_eq!(imports[0].symbols[1].alias.as_deref(), Some("value"));
        assert_eq!(imports[0].symbols[2].name, "value");
        assert_eq!(imports[0].symbols[2].alias.as_deref(), Some("foo"));
    }

    #[test]
    fn nested_namespace_and_class_methods_are_emitted_by_recursive_walk() {
        let source = br#"
namespace Internal {
    export function hidden() {}
}

class Api {
    method() {}
}

function topLevel() {}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols.iter().any(|s| s.name == "Api"));
        assert!(symbols.iter().any(|s| s.name == "topLevel"));
        assert!(symbols.iter().any(|s| s.name == "hidden"));
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "method" && s.kind == SymbolKind::Method)
        );
    }

    #[test]
    fn extract_exports_collects_declarations_and_reexport_aliases() {
        let source = br#"
export { foo as bar } from "./foo";
export * from "./other";
export type { ShapeLike } from "./types";
export function declared() {}
export interface DeclaredShape {}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert!(exports.iter().any(|e| e.name == "declared"));
        assert!(exports.iter().any(|e| e.name == "DeclaredShape"));
        assert!(exports.iter().any(|e| e.name == "bar"));
    }

    #[test]
    fn default_anonymous_export_is_ignored_but_named_default_class_is_captured() {
        let source = br#"
export default function () {
    return 42;
}

export default class NamedDefault {}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "NamedDefault");
        assert_eq!(exports[0].kind, SymbolKind::Class);
    }

    #[test]
    fn side_effect_and_default_named_imports_are_separated_correctly() {
        let source = br#"
import "./polyfill";
import Client, { connect as openConnection } from "./client";
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "./polyfill");
        assert!(imports[0].symbols.is_empty());

        assert_eq!(imports[1].source, "./client");
        assert_eq!(imports[1].symbols.len(), 2);
        assert_eq!(imports[1].symbols[0].name, "default");
        assert_eq!(imports[1].symbols[0].alias.as_deref(), Some("Client"));
        assert_eq!(imports[1].symbols[1].name, "connect");
        assert_eq!(
            imports[1].symbols[1].alias.as_deref(),
            Some("openConnection")
        );
    }
}
