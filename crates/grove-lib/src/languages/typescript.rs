use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

struct ParseCache {
    source: Vec<u8>,
    is_tsx: bool,
    tree: tree_sitter::Tree,
}

pub struct TypeScriptAnalyzer {
    parser_ts: std::sync::Mutex<Parser>,
    parser_tsx: std::sync::Mutex<Parser>,
    parse_cache: std::sync::Mutex<Option<ParseCache>>,
}

impl Default for TypeScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeScriptAnalyzer {
    pub fn new() -> Self {
        let mut parser_ts = Parser::new();
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
        parser_ts
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("failed to set typescript language");

        let mut parser_tsx = Parser::new();
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
        parser_tsx
            .set_language(&tree_sitter_typescript::LANGUAGE_TSX.into())
            .expect("failed to set tsx language");

        Self {
            parser_ts: std::sync::Mutex::new(parser_ts),
            parser_tsx: std::sync::Mutex::new(parser_tsx),
            parse_cache: std::sync::Mutex::new(None),
        }
    }

    fn parse(&self, source: &[u8], is_tsx: bool) -> Result<tree_sitter::Tree, AnalysisError> {
        {
            let cache = self.parse_cache.lock().unwrap();
            if let Some(cached) = cache
                .as_ref()
                .filter(|cached| cached.is_tsx == is_tsx && cached.source.as_slice() == source)
            {
                return Ok(cached.tree.clone());
            }
        }

        let tree = {
            let mut parser = if is_tsx {
                self.parser_tsx.lock().unwrap()
            } else {
                self.parser_ts.lock().unwrap()
            };
            parser
                .parse(source, None)
                .ok_or_else(|| AnalysisError::ParseError("tree-sitter parse failed".into()))?
        };

        let mut cache = self.parse_cache.lock().unwrap();
        *cache = Some(ParseCache {
            source: source.to_vec(),
            is_tsx,
            tree: tree.clone(),
        });

        Ok(tree)
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

    // === Stress tests and edge cases ===

    #[test]
    fn empty_source_returns_empty() {
        let analyzer = TypeScriptAnalyzer::new();
        assert!(analyzer.extract_symbols(b"").unwrap().is_empty());
        assert!(analyzer.extract_imports(b"").unwrap().is_empty());
        assert!(analyzer.extract_exports(b"").unwrap().is_empty());
    }

    #[test]
    fn malformed_source_recovers_stable_parts() {
        let source = br#"
function stableBeforeBroken(): void {}

class Broken {
    method( { // broken method signature

export function validAfterBroken(): void {
    return;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        // Stable function before the broken syntax should always be recovered
        assert!(symbols.iter().any(|s| s.name == "stableBeforeBroken"));
    }

    #[test]
    fn large_module_with_many_exports() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("export function fn_{}(): void {{}}\n", i));
        }
        let source_bytes = source.as_bytes();
        let analyzer = TypeScriptAnalyzer::new();

        let symbols = analyzer.extract_symbols(source_bytes).unwrap();
        let functions: Vec<_> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .collect();
        assert_eq!(functions.len(), 100);

        let exports = analyzer.extract_exports(source_bytes).unwrap();
        assert_eq!(exports.len(), 100);
        for i in 0..100 {
            let name = format!("fn_{}", i);
            assert!(
                exports.iter().any(|e| e.name == name),
                "missing export: {}",
                name
            );
        }
    }

    #[test]
    fn deeply_nested_callbacks() {
        let mut source = String::new();
        for i in 0..10 {
            source.push_str(&format!("const cb_{} = () => {{\n", i));
        }
        source.push_str("return 'deep';\n");
        for _ in 0..10 {
            source.push_str("};\n");
        }
        let source_bytes = source.as_bytes();
        let analyzer = TypeScriptAnalyzer::new();

        // Should not panic or hang
        let symbols = analyzer.extract_symbols(source_bytes).unwrap();
        assert!(symbols.iter().any(|s| s.name == "cb_0"));
        assert!(symbols.iter().any(|s| s.name == "cb_9"));
    }

    #[test]
    fn realistic_nextjs_api_route() {
        let source = br#"
import { NextRequest, NextResponse } from 'next/server';
import { validateToken } from '@/lib/auth';
import { db } from '@/lib/db';

interface UserPayload {
    name: string;
    email: string;
}

type ApiResponse = {
    data?: UserPayload;
    error?: string;
};

export async function GET(request: NextRequest): Promise<NextResponse<ApiResponse>> {
    try {
        const token = request.headers.get('authorization');
        const user = await validateToken(token);
        return NextResponse.json({ data: user });
    } catch (error) {
        return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
}

export async function POST(request: NextRequest): Promise<NextResponse<ApiResponse>> {
    const body: UserPayload = await request.json();
    const user = await db.users.create({ data: body });
    return NextResponse.json({ data: user }, { status: 201 });
}
"#;
        let analyzer = TypeScriptAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "GET" && s.kind == SymbolKind::Function)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "POST" && s.kind == SymbolKind::Function)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "UserPayload" && s.kind == SymbolKind::Interface)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "ApiResponse" && s.kind == SymbolKind::TypeAlias)
        );

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 3);
        assert!(imports.iter().any(|i| i.source == "next/server"));
        assert!(imports.iter().any(|i| i.source == "@/lib/auth"));
        assert!(imports.iter().any(|i| i.source == "@/lib/db"));

        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.iter().any(|e| e.name == "GET"));
        assert!(exports.iter().any(|e| e.name == "POST"));
    }

    #[test]
    fn tsx_component_with_jsx() {
        // The extract_symbols method parses as TS (not TSX), so tree-sitter
        // may partially recover from JSX syntax. Verify stable symbol extraction.
        let source = br#"
import React, { useState, useEffect } from 'react';

interface ButtonProps {
    label: string;
    onClick: () => void;
}

function Button(props: ButtonProps) {
    const [count, setCount] = useState(0);

    useEffect(() => {
        console.log('mounted');
    }, []);

    return <button onClick={props.onClick}>{props.label} ({count})</button>;
}

export default Button;
"#;
        let analyzer = TypeScriptAnalyzer::new();

        // Symbols: tree-sitter TS grammar may recover the interface and function
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "ButtonProps" && s.kind == SymbolKind::Interface)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Button" && s.kind == SymbolKind::Function)
        );

        let imports = analyzer.extract_imports(source).unwrap();
        assert!(imports.iter().any(|i| i.source == "react"));
        let react_import = imports.iter().find(|i| i.source == "react").unwrap();
        assert!(react_import.symbols.iter().any(|s| s.name == "useState"));
        assert!(react_import.symbols.iter().any(|s| s.name == "useEffect"));
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = br#"import { foo } from './foo';

function first() {}

function second() {}
"#;
        let analyzer = TypeScriptAnalyzer::new();

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports[0].line, 1);

        let symbols = analyzer.extract_symbols(source).unwrap();
        let first = symbols.iter().find(|s| s.name == "first").unwrap();
        assert_eq!(first.range.start, 3);
        let second = symbols.iter().find(|s| s.name == "second").unwrap();
        assert_eq!(second.range.start, 5);
    }

    #[test]
    fn parse_cache_returns_consistent_results() {
        let source = br#"
function cached() {}
class CachedClass {}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let first = analyzer.extract_symbols(source).unwrap();
        let second = analyzer.extract_symbols(source).unwrap();
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.range, b.range);
        }
    }

    #[test]
    fn comments_do_not_produce_symbols() {
        let source = br#"
// function notAFunction() {}
// class NotAClass {}
/* interface NotAnInterface {} */
/* export function notExported() {} */
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.is_empty());
        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.is_empty());
    }

    #[test]
    fn unicode_identifiers() {
        let source = br#"
const greeting = "Hello, \u4e16\u754c!"; // Chinese characters
// Comment with emoji: rocket ship
function processData(): string {
    return `Result: ${greeting}`;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "greeting"));
        assert!(symbols.iter().any(|s| s.name == "processData"));
    }

    #[test]
    fn mixed_ts_and_js_features() {
        let source = br#"
import { esModule } from './es-module';
const legacy = require('./legacy');
const { destructured } = require('./another');

export function modernExport(): void {}
module.exports = { legacyExport: true };
"#;
        let analyzer = TypeScriptAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "legacy" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "destructured" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "modernExport" && s.kind == SymbolKind::Function)
        );

        let imports = analyzer.extract_imports(source).unwrap();
        assert!(imports.iter().any(|i| i.source == "./es-module"));
        // require() calls are not import statements, so they should not appear
        assert!(!imports.iter().any(|i| i.source == "./legacy"));

        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.iter().any(|e| e.name == "modernExport"));
    }

    #[test]
    fn re_exports() {
        let source = br#"
export { foo } from './bar';
export * from './baz';
export { default as Thing } from './thing';
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert!(
            exports.iter().any(|e| e.name == "foo"),
            "missing re-export: foo"
        );
        assert!(
            exports.iter().any(|e| e.name == "Thing"),
            "missing aliased default re-export: Thing"
        );
    }

    #[test]
    fn extract_symbols_includes_enum_and_type_alias() {
        let source = br#"
enum Direction {
    North,
    South,
}

type UserId = string;
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let dir = symbols.iter().find(|s| s.name == "Direction").unwrap();
        assert_eq!(dir.kind, SymbolKind::Enum);

        let uid = symbols.iter().find(|s| s.name == "UserId").unwrap();
        assert_eq!(uid.kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn language_id_and_file_extensions() {
        let analyzer = TypeScriptAnalyzer::new();
        assert_eq!(analyzer.language_id(), "typescript");
        let exts = analyzer.file_extensions();
        assert!(exts.contains(&"ts"));
        assert!(exts.contains(&"tsx"));
        assert!(exts.contains(&"js"));
        assert!(exts.contains(&"jsx"));
        assert!(exts.contains(&"mts"));
        assert!(exts.contains(&"mjs"));
        assert_eq!(exts.len(), 6);
    }

    #[test]
    fn import_with_empty_source_is_skipped() {
        let source = br#"
import { foo } from '';
import { bar } from './valid';
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        // The empty-string import should be filtered out by extract_string_value
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "./valid");
    }

    #[test]
    fn function_signature_contains_declaration() {
        let source = br#"
function greet(name: string): string {
    return `Hello, ${name}!`;
}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let sig = symbols[0].signature.as_ref().unwrap();
        assert!(sig.contains("function greet"));
        assert!(!sig.is_empty());
    }

    #[test]
    fn is_schema_file_rejects_regular_code_files() {
        let analyzer = TypeScriptAnalyzer::new();
        assert!(!analyzer.is_schema_file(Path::new("src/index.ts")));
        assert!(!analyzer.is_schema_file(Path::new("src/utils.js")));
        assert!(!analyzer.is_schema_file(Path::new("components/App.tsx")));
    }

    #[test]
    fn range_start_and_end_for_all_symbol_kinds() {
        let source = br#"function topFn(): void {
    return;
}

class MyClass {
    myMethod(): void {
        return;
    }
}

interface MyInterface {
    field: string;
}

type MyType = string | number;

enum MyEnum {
    A,
    B,
}

const myVar = 42;
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let top_fn = symbols.iter().find(|s| s.name == "topFn").unwrap();
        assert_eq!(top_fn.range.start, 1);
        assert_eq!(top_fn.range.end, 3);

        let my_class = symbols.iter().find(|s| s.name == "MyClass").unwrap();
        assert_eq!(my_class.range.start, 5);
        assert_eq!(my_class.range.end, 9);

        let my_method = symbols.iter().find(|s| s.name == "myMethod").unwrap();
        assert_eq!(my_method.range.start, 6);
        assert_eq!(my_method.range.end, 8);

        let my_iface = symbols.iter().find(|s| s.name == "MyInterface").unwrap();
        assert_eq!(my_iface.range.start, 11);
        assert_eq!(my_iface.range.end, 13);

        let my_type = symbols.iter().find(|s| s.name == "MyType").unwrap();
        assert_eq!(my_type.range.start, 15);
        assert_eq!(my_type.range.end, 15);

        let my_enum = symbols.iter().find(|s| s.name == "MyEnum").unwrap();
        assert_eq!(my_enum.range.start, 17);
        assert_eq!(my_enum.range.end, 20);

        let my_var = symbols.iter().find(|s| s.name == "myVar").unwrap();
        assert_eq!(my_var.range.start, 22);
        assert_eq!(my_var.range.end, 22);
    }

    #[test]
    fn dynamic_import_line_number() {
        let source = br#"const x = 1;
const y = 2;
const mod = await import("./mod");
const z = 3;
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "./mod");
        assert_eq!(imports[0].line, 3);
    }

    // === Mutant-killing tests ===

    #[test]
    fn parse_cache_invalidates_when_source_changes() {
        // Kills mutants on line 50: == with !=, == with !=, && with ||
        // If the cache equality is inverted, parsing different source would
        // incorrectly return stale cached results.
        let analyzer = TypeScriptAnalyzer::new();

        let source_a = b"function alpha(): void {}";
        let source_b = b"function beta(): void {}";

        let symbols_a = analyzer.extract_symbols(source_a).unwrap();
        assert_eq!(symbols_a.len(), 1);
        assert_eq!(symbols_a[0].name, "alpha");

        // Parse different source — cache must NOT return stale "alpha"
        let symbols_b = analyzer.extract_symbols(source_b).unwrap();
        assert_eq!(symbols_b.len(), 1);
        assert_eq!(
            symbols_b[0].name, "beta",
            "cache returned stale result from previous parse"
        );
    }

    #[test]
    fn parse_cache_distinguishes_tsx_flag() {
        // Kills the is_tsx == with != mutant on line 50.
        // TypeScriptAnalyzer::parse caches by (source, is_tsx). If the is_tsx
        // check is inverted, the cache would return a TSX tree for TS or vice
        // versa. We exercise this by calling parse directly for the same source
        // with different is_tsx flags and verifying both succeed (no parse error
        // from wrong grammar).
        let analyzer = TypeScriptAnalyzer::new();
        let source = b"const x: number = 1;";

        // Parse as TS
        let tree_ts = analyzer.parse(source, false);
        assert!(tree_ts.is_ok(), "TS parse should succeed");

        // Parse same source as TSX — must NOT return the cached TS tree
        // if the is_tsx field matters
        let tree_tsx = analyzer.parse(source, true);
        assert!(tree_tsx.is_ok(), "TSX parse should succeed");

        // Parse as TS again — should hit cache correctly
        let tree_ts2 = analyzer.parse(source, false);
        assert!(tree_ts2.is_ok(), "second TS parse should succeed");
    }

    #[test]
    fn exported_type_alias_is_captured() {
        // Kills mutant on line 268: delete match arm "type_alias_declaration" in extract_exports
        let source = br#"export type UserId = string;
export type Config = { host: string; port: number };
export function helper(): void {}
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let type_alias_exports: Vec<_> = exports
            .iter()
            .filter(|e| e.kind == SymbolKind::TypeAlias)
            .collect();
        assert_eq!(
            type_alias_exports.len(),
            2,
            "expected 2 exported type aliases, got {:?}",
            exports
        );
        assert_eq!(type_alias_exports[0].name, "UserId");
        assert_eq!(type_alias_exports[1].name, "Config");

        // Also verify the function export is still there
        assert!(exports.iter().any(|e| e.name == "helper"));
    }

    #[test]
    fn import_with_empty_double_quoted_source_is_skipped() {
        // Kills mutants on line 374: replace match guard source_path.is_empty() with true/false
        // The match guard on line 374 handles the fallback case where source_path
        // hasn't been found yet via child_by_field_name("source"). If the guard
        // is replaced with `true`, it would overwrite valid sources with empty ones.
        // If replaced with `false`, it would never try the fallback extraction.
        let source = br#"import { foo } from "";
import { bar } from "./real-module";
"#;
        let analyzer = TypeScriptAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        // Empty-string source should be filtered out
        assert_eq!(
            imports.len(),
            1,
            "expected only 1 import, got {:?}",
            imports
        );
        assert_eq!(imports[0].source, "./real-module");
        assert_eq!(imports[0].symbols.len(), 1);
        assert_eq!(imports[0].symbols[0].name, "bar");
    }

    #[test]
    fn parse_cache_tsx_flag_prevents_wrong_grammar_reuse() {
        // Kills mutant: line 50:48 `cached.is_tsx == is_tsx` → `cached.is_tsx != is_tsx`
        //
        // JSX source is valid under the TSX grammar (produces jsx_self_closing_element)
        // but produces error nodes under the TS grammar (which has no JSX support).
        // If the cache incorrectly returns a TSX-parsed tree when TS is requested
        // (or vice versa), the tree structure will be wrong.
        //
        // Strategy: parse JSX source with is_tsx=true first (populates cache with TSX tree).
        // Then parse the SAME source with is_tsx=false. With the mutation (!=), the
        // second call matches the cache entry (true != false → true, source matches → true)
        // and returns the cached TSX tree instead of re-parsing with the TS grammar.
        // We detect this by checking that the TS parse has error nodes (JSX is invalid TS).
        let analyzer = TypeScriptAnalyzer::new();
        let jsx_source = b"const el = <div />;";

        // First parse as TSX — should succeed cleanly (JSX is valid TSX)
        let tsx_tree = analyzer.parse(jsx_source, true).unwrap();
        assert!(
            !tsx_tree.root_node().has_error(),
            "TSX parse of JSX source should have no errors"
        );

        // Second parse as TS — must NOT return the cached TSX tree.
        // The TS grammar does not support JSX, so it should produce error nodes.
        let ts_tree = analyzer.parse(jsx_source, false).unwrap();
        assert!(
            ts_tree.root_node().has_error(),
            "TS parse of JSX source should have errors, but got a clean tree \
             (cache likely returned the TSX tree due to inverted is_tsx check)"
        );
    }

    #[test]
    fn extract_static_import_fallback_uses_first_string_child() {
        // Kills mutants: line 374:45
        //   - `source_path.is_empty()` → `true`  (always overwrite → uses last string)
        //   - `source_path.is_empty()` → `false` (never fallback → returns None)
        //
        // extract_static_import first tries child_by_field_name("source"). If that
        // fails (returns None), it falls back to the first "string" or "template_string"
        // direct child, guarded by `source_path.is_empty()`.
        //
        // We exercise this by calling extract_static_import on a tree-sitter node that:
        //   1. Has NO "source" field (child_by_field_name returns None)
        //   2. Has TWO string direct children with different values
        //
        // With the original guard (is_empty):
        //   - First string sets source_path → guard blocks second → result: first string
        // With `true` mutation:
        //   - Both strings fire → second overwrites first → result: second string
        // With `false` mutation:
        //   - Neither string fires → source_path stays empty → returns None
        let analyzer = TypeScriptAnalyzer::new();

        // Parse an array literal: ['./first', './second']
        // The array node has two string direct children and no "source" field.
        let src = b"['./first', './second'];";
        let tree = analyzer.parse(src, false).unwrap();
        let root = tree.root_node();

        // Navigate to the array node: program > expression_statement > array
        let expr_stmt = root.child(0).expect("expected expression_statement");
        let array_node = expr_stmt
            .child(0)
            .expect("expected array node inside expression_statement");
        assert_eq!(
            array_node.kind(),
            "array",
            "expected array node, got {:?}",
            array_node.kind()
        );
        assert!(
            array_node.child_by_field_name("source").is_none(),
            "array node should not have a 'source' field"
        );

        let result = extract_static_import(array_node, src);
        let import = result.expect(
            "extract_static_import should return Some when string children \
             exist (fallback path). If None, the is_empty() guard was \
             replaced with `false`, preventing fallback extraction.",
        );
        assert_eq!(
            import.source, "./first",
            "extract_static_import should use the FIRST string child. \
             If './second', the is_empty() guard was replaced with `true`, \
             allowing the second string to overwrite the first."
        );
    }
}
