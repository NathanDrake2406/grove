use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

struct ParseCache {
    source: Vec<u8>,
    tree: tree_sitter::Tree,
}

pub struct PythonAnalyzer {
    parser: std::sync::Mutex<Parser>,
    parse_cache: std::sync::Mutex<Option<ParseCache>>,
}

impl Default for PythonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PythonAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("failed to set python language");
        Self {
            parser: std::sync::Mutex::new(parser),
            parse_cache: std::sync::Mutex::new(None),
        }
    }

    fn parse(&self, source: &[u8]) -> Result<tree_sitter::Tree, AnalysisError> {
        {
            let cache = self.parse_cache.lock().unwrap();
            if let Some(cached) = cache
                .as_ref()
                .filter(|cached| cached.source.as_slice() == source)
            {
                return Ok(cached.tree.clone());
            }
        }

        let tree = {
            let mut parser = self.parser.lock().unwrap();
            parser
                .parse(source, None)
                .ok_or_else(|| AnalysisError::ParseError("python parse failed".into()))?
        };

        let mut cache = self.parse_cache.lock().unwrap();
        *cache = Some(ParseCache {
            source: source.to_vec(),
            tree: tree.clone(),
        });

        Ok(tree)
    }
}

fn get_signature_line(source: &[u8], start: usize) -> String {
    let slice = &source[start..];
    let text = String::from_utf8_lossy(slice);
    text.lines().next().unwrap_or("").to_string()
}

fn is_all_caps_constant(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_uppercase() || c == '_' || c.is_ascii_digit())
        && name.chars().any(|c| c.is_uppercase())
}

impl LanguageAnalyzer for PythonAnalyzer {
    fn language_id(&self) -> &str {
        "python"
    }

    fn file_extensions(&self) -> &[&str] {
        &["py", "pyi"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            extract_top_level_symbol(child, source, &mut symbols);
        }

        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            match child.kind() {
                "import_statement" => {
                    extract_import_statement(child, source, &mut imports);
                }
                "import_from_statement" => {
                    extract_import_from_statement(child, source, &mut imports);
                }
                _ => {}
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let symbols = self.extract_symbols(source)?;

        // Phase 1: Check for __all__
        if let Some(all_names) = extract_dunder_all(root, source) {
            let symbol_map: std::collections::HashMap<&str, &Symbol> =
                symbols.iter().map(|s| (s.name.as_str(), s)).collect();

            return Ok(all_names
                .into_iter()
                .map(|name| {
                    if let Some(sym) = symbol_map.get(name.as_str()) {
                        ExportedSymbol {
                            name,
                            kind: sym.kind,
                            signature: sym.signature.clone(),
                        }
                    } else {
                        // Re-exported name not found in symbols — default to Variable
                        ExportedSymbol {
                            name,
                            kind: SymbolKind::Variable,
                            signature: None,
                        }
                    }
                })
                .collect());
        }

        // Phase 2: No __all__ — export all non-underscore-prefixed symbols
        Ok(symbols
            .into_iter()
            .filter(|s| !s.name.starts_with('_'))
            .map(|s| ExportedSymbol {
                name: s.name,
                kind: s.kind,
                signature: s.signature,
            })
            .collect())
    }

    fn is_schema_file(&self, path: &Path) -> bool {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        matches!(
            filename.as_str(),
            "pyproject.toml"
                | "setup.py"
                | "setup.cfg"
                | "requirements.txt"
                | "Pipfile"
                | "Pipfile.lock"
                | "poetry.lock"
                | "uv.lock"
        )
    }
}

// === Symbol extraction ===

fn extract_top_level_symbol(node: tree_sitter::Node<'_>, source: &[u8], symbols: &mut Vec<Symbol>) {
    match node.kind() {
        "function_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                symbols.push(Symbol {
                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                    kind: SymbolKind::Function,
                    range: LineRange {
                        start: node.start_position().row as u32 + 1,
                        end: node.end_position().row as u32 + 1,
                    },
                    signature: Some(get_signature_line(source, node.start_byte())),
                });
            }
        }
        "class_definition" => {
            extract_class_symbol(node, node, source, symbols);
        }
        "decorated_definition" => {
            if let Some(definition) = node.child_by_field_name("definition") {
                match definition.kind() {
                    "function_definition" => {
                        if let Some(name_node) = definition.child_by_field_name("name") {
                            symbols.push(Symbol {
                                name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                kind: SymbolKind::Function,
                                range: LineRange {
                                    start: node.start_position().row as u32 + 1,
                                    end: node.end_position().row as u32 + 1,
                                },
                                signature: Some(get_signature_line(
                                    source,
                                    definition.start_byte(),
                                )),
                            });
                        }
                    }
                    "class_definition" => {
                        extract_class_symbol(node, definition, source, symbols);
                    }
                    _ => {}
                }
            }
        }
        "expression_statement" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "assignment"
                    && let Some(left) = child.child_by_field_name("left")
                    && left.kind() == "identifier"
                {
                    let name = left.utf8_text(source).unwrap_or("").to_string();
                    if name == "__all__" {
                        continue;
                    }
                    let kind = if is_all_caps_constant(&name) {
                        SymbolKind::Constant
                    } else {
                        SymbolKind::Variable
                    };
                    symbols.push(Symbol {
                        name,
                        kind,
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

/// Extract a class symbol and its methods. `range_node` provides the line range
/// (the outer `decorated_definition` when decorators are present, otherwise the
/// `class_definition` itself). `class_node` is always the `class_definition`.
fn extract_class_symbol(
    range_node: tree_sitter::Node<'_>,
    class_node: tree_sitter::Node<'_>,
    source: &[u8],
    symbols: &mut Vec<Symbol>,
) {
    if let Some(name_node) = class_node.child_by_field_name("name") {
        symbols.push(Symbol {
            name: name_node.utf8_text(source).unwrap_or("").to_string(),
            kind: SymbolKind::Class,
            range: LineRange {
                start: range_node.start_position().row as u32 + 1,
                end: range_node.end_position().row as u32 + 1,
            },
            signature: None,
        });

        if let Some(body) = class_node.child_by_field_name("body") {
            let mut body_cursor = body.walk();
            for body_child in body.children(&mut body_cursor) {
                extract_method(body_child, source, symbols);
            }
        }
    }
}

fn extract_method(node: tree_sitter::Node<'_>, source: &[u8], symbols: &mut Vec<Symbol>) {
    match node.kind() {
        "function_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                symbols.push(Symbol {
                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                    kind: SymbolKind::Method,
                    range: LineRange {
                        start: node.start_position().row as u32 + 1,
                        end: node.end_position().row as u32 + 1,
                    },
                    signature: Some(get_signature_line(source, node.start_byte())),
                });
            }
        }
        "decorated_definition" => {
            if let Some(definition) = node.child_by_field_name("definition")
                && definition.kind() == "function_definition"
                && let Some(name_node) = definition.child_by_field_name("name")
            {
                symbols.push(Symbol {
                    name: name_node.utf8_text(source).unwrap_or("").to_string(),
                    kind: SymbolKind::Method,
                    range: LineRange {
                        start: node.start_position().row as u32 + 1,
                        end: node.end_position().row as u32 + 1,
                    },
                    signature: Some(get_signature_line(source, definition.start_byte())),
                });
            }
        }
        _ => {}
    }
}

// === Import extraction ===

/// Extract imports from `import x, y, z` statements.
/// One `Import` per name entry.
fn extract_import_statement(node: tree_sitter::Node<'_>, source: &[u8], imports: &mut Vec<Import>) {
    let mut cursor = node.walk();
    for child in node.children_by_field_name("name", &mut cursor) {
        match child.kind() {
            "dotted_name" => {
                imports.push(Import {
                    source: child.utf8_text(source).unwrap_or("").to_string(),
                    symbols: vec![],
                    line: child.start_position().row as u32 + 1,
                });
            }
            "aliased_import" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let source_path = name_node.utf8_text(source).unwrap_or("").to_string();
                    let alias = child
                        .child_by_field_name("alias")
                        .and_then(|n| n.utf8_text(source).ok())
                        .map(|s| s.to_string());
                    imports.push(Import {
                        source: source_path,
                        symbols: alias
                            .map(|a| {
                                vec![ImportedSymbol {
                                    name: a,
                                    alias: None,
                                }]
                            })
                            .unwrap_or_default(),
                        line: child.start_position().row as u32 + 1,
                    });
                }
            }
            _ => {}
        }
    }
}

/// Extract imports from `from x import y, z` statements.
/// One `Import` per statement.
fn extract_import_from_statement(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    imports: &mut Vec<Import>,
) {
    let module_name = match node.child_by_field_name("module_name") {
        Some(mn) => mn.utf8_text(source).unwrap_or("").to_string(),
        None => return,
    };

    // Check for wildcard import
    let mut child_cursor = node.walk();
    for child in node.children(&mut child_cursor) {
        if child.kind() == "wildcard_import" {
            imports.push(Import {
                source: module_name,
                symbols: vec![ImportedSymbol {
                    name: "*".to_string(),
                    alias: None,
                }],
                line: node.start_position().row as u32 + 1,
            });
            return;
        }
    }

    // Extract named imports
    let mut symbols = Vec::new();
    let mut name_cursor = node.walk();
    for child in node.children_by_field_name("name", &mut name_cursor) {
        match child.kind() {
            "dotted_name" => {
                symbols.push(ImportedSymbol {
                    name: child.utf8_text(source).unwrap_or("").to_string(),
                    alias: None,
                });
            }
            "aliased_import" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    let alias = child
                        .child_by_field_name("alias")
                        .and_then(|n| n.utf8_text(source).ok())
                        .map(|s| s.to_string());
                    symbols.push(ImportedSymbol { name, alias });
                }
            }
            _ => {}
        }
    }

    imports.push(Import {
        source: module_name,
        symbols,
        line: node.start_position().row as u32 + 1,
    });
}

// === Export extraction ===

/// Walk top-level statements looking for `__all__ = [...]` or `__all__ = (...)`.
/// Returns `Some(names)` if found, `None` otherwise.
fn extract_dunder_all(root: tree_sitter::Node<'_>, source: &[u8]) -> Option<Vec<String>> {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        if child.kind() != "expression_statement" {
            continue;
        }
        let mut stmt_cursor = child.walk();
        for stmt_child in child.children(&mut stmt_cursor) {
            if stmt_child.kind() != "assignment" {
                continue;
            }
            let Some(left) = stmt_child.child_by_field_name("left") else {
                continue;
            };
            if left.kind() != "identifier" || left.utf8_text(source).unwrap_or("") != "__all__" {
                continue;
            }
            let Some(right) = stmt_child.child_by_field_name("right") else {
                continue;
            };
            if right.kind() != "list" && right.kind() != "tuple" {
                continue;
            }
            let mut names = Vec::new();
            let mut list_cursor = right.walk();
            for list_child in right.children(&mut list_cursor) {
                if list_child.kind() == "string"
                    && let Some(content) = extract_string_content(list_child, source)
                {
                    names.push(content);
                }
            }
            return Some(names);
        }
    }
    None
}

/// Extract the text content from a string node, stripping quotes.
fn extract_string_content(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "string_content" {
            return Some(child.utf8_text(source).unwrap_or("").to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_function_symbols() {
        let source = br#"def process(data):
    return data

async def fetch(url):
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "process");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert!(
            symbols[0]
                .signature
                .as_ref()
                .unwrap()
                .contains("def process")
        );
        assert_eq!(symbols[1].name, "fetch");
        assert_eq!(symbols[1].kind, SymbolKind::Function);
        assert!(
            symbols[1]
                .signature
                .as_ref()
                .unwrap()
                .contains("async def fetch")
        );
    }

    #[test]
    fn extracts_class_symbols() {
        let source = br#"class Foo:
    pass

class Bar(Base):
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let classes: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Class)
            .collect();
        assert_eq!(classes.len(), 2);
        assert_eq!(classes[0].name, "Foo");
        assert_eq!(classes[1].name, "Bar");
    }

    #[test]
    fn extracts_methods_from_class_body() {
        let source = br#"class MyClass:
    def method_a(self):
        pass

    def method_b(self, x):
        return x
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "MyClass");
        assert_eq!(symbols[0].kind, SymbolKind::Class);
        assert_eq!(symbols[1].name, "method_a");
        assert_eq!(symbols[1].kind, SymbolKind::Method);
        assert_eq!(symbols[2].name, "method_b");
        assert_eq!(symbols[2].kind, SymbolKind::Method);
        assert!(
            symbols[2]
                .signature
                .as_ref()
                .unwrap()
                .contains("def method_b")
        );
    }

    #[test]
    fn extracts_async_class_method_as_method() {
        let source = br#"class Client:
    async def fetch(self, url):
        return url
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let method = symbols.iter().find(|s| s.name == "fetch").unwrap();
        assert_eq!(method.kind, SymbolKind::Method);
        assert!(
            method
                .signature
                .as_ref()
                .unwrap()
                .contains("async def fetch")
        );
    }

    #[test]
    fn extracts_decorated_definitions() {
        let source = br#"@decorator
def decorated_func():
    pass

@app.route("/")
class DecoratedClass:
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "decorated_func");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        // Decorated definition range includes the decorator line
        assert_eq!(symbols[0].range.start, 1);
        assert_eq!(symbols[1].name, "DecoratedClass");
        assert_eq!(symbols[1].kind, SymbolKind::Class);
        assert_eq!(symbols[1].range.start, 5);
    }

    #[test]
    fn extracts_imports() {
        let source = br#"import os
import sys, os
import os.path as osp
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 4);
        assert_eq!(imports[0].source, "os");
        assert!(imports[0].symbols.is_empty());
        assert_eq!(imports[1].source, "sys");
        assert_eq!(imports[2].source, "os");
        assert_eq!(imports[3].source, "os.path");
        assert_eq!(imports[3].symbols[0].name, "osp");
    }

    #[test]
    fn extracts_from_imports() {
        let source = br#"from os.path import join, exists as ex
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "os.path");
        assert_eq!(imports[0].symbols.len(), 2);
        assert_eq!(imports[0].symbols[0].name, "join");
        assert_eq!(imports[0].symbols[0].alias, None);
        assert_eq!(imports[0].symbols[1].name, "exists");
        assert_eq!(imports[0].symbols[1].alias, Some("ex".to_string()));
    }

    #[test]
    fn extracts_relative_imports() {
        let source = br#"from . import utils
from ..pkg import foo
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, ".");
        assert_eq!(imports[0].symbols[0].name, "utils");
        assert_eq!(imports[1].source, "..pkg");
        assert_eq!(imports[1].symbols[0].name, "foo");
    }

    #[test]
    fn extracts_wildcard_import() {
        let source = br#"from os import *
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "os");
        assert_eq!(imports[0].symbols.len(), 1);
        assert_eq!(imports[0].symbols[0].name, "*");
    }

    #[test]
    fn exports_with_dunder_all() {
        let source = br#"__all__ = ["Foo", "bar"]

class Foo:
    pass

def bar():
    pass

def _private():
    pass

def baz():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Foo", "bar"]);
        assert_eq!(exports[0].kind, SymbolKind::Class);
        assert_eq!(exports[1].kind, SymbolKind::Function);
    }

    #[test]
    fn exports_fallback_no_dunder_all() {
        let source = br#"class Foo:
    pass

def bar():
    pass

def _private():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Foo"));
        assert!(names.contains(&"bar"));
        assert!(!names.contains(&"_private"));
    }

    #[test]
    fn underscore_names_excluded_from_fallback_exports() {
        let source = br#"def public():
    pass

def _private():
    pass

def __dunder__():
    pass

_PRIVATE_CONST = 42
"#;
        let analyzer = PythonAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["public"]);
    }

    #[test]
    fn constants_detected_by_all_caps() {
        let source = br#"MAX_SIZE = 1024
name = "grove"
DEBUG = True
_PRIVATE = 1
HTTP2_PORT = 8443
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols[0].name, "MAX_SIZE");
        assert_eq!(symbols[0].kind, SymbolKind::Constant);
        assert_eq!(symbols[1].name, "name");
        assert_eq!(symbols[1].kind, SymbolKind::Variable);
        assert_eq!(symbols[2].name, "DEBUG");
        assert_eq!(symbols[2].kind, SymbolKind::Constant);
        assert_eq!(symbols[3].name, "_PRIVATE");
        assert_eq!(symbols[3].kind, SymbolKind::Constant);
        assert_eq!(symbols[4].name, "HTTP2_PORT");
        assert_eq!(symbols[4].kind, SymbolKind::Constant);
    }

    #[test]
    fn empty_source_returns_empty() {
        let analyzer = PythonAnalyzer::new();
        assert!(analyzer.extract_symbols(b"").unwrap().is_empty());
        assert!(analyzer.extract_imports(b"").unwrap().is_empty());
        assert!(analyzer.extract_exports(b"").unwrap().is_empty());
    }

    #[test]
    fn malformed_source_recovers() {
        let source = br#"def stable_func():
    pass

def broken_func(:
    pass

def another_func():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "stable_func"));
    }

    #[test]
    fn schema_file_detection() {
        let analyzer = PythonAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("pyproject.toml")));
        assert!(analyzer.is_schema_file(Path::new("setup.py")));
        assert!(analyzer.is_schema_file(Path::new("setup.cfg")));
        assert!(analyzer.is_schema_file(Path::new("requirements.txt")));
        assert!(analyzer.is_schema_file(Path::new("Pipfile")));
        assert!(analyzer.is_schema_file(Path::new("Pipfile.lock")));
        assert!(analyzer.is_schema_file(Path::new("poetry.lock")));
        assert!(analyzer.is_schema_file(Path::new("uv.lock")));
        assert!(analyzer.is_schema_file(Path::new("myproject/pyproject.toml")));
        assert!(!analyzer.is_schema_file(Path::new("main.py")));
        assert!(!analyzer.is_schema_file(Path::new("pyproject.toml.bak")));
    }

    #[test]
    fn dunder_all_with_tuple() {
        let source = br#"__all__ = ("Foo", "Bar")

class Foo:
    pass

def Bar():
    pass

def Baz():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Foo", "Bar"]);
    }

    #[test]
    fn realistic_python_module() {
        let source = br#""""A realistic Python module with various constructs."""

import os
import sys
from typing import List, Optional
from pathlib import Path

__all__ = ["UserService", "create_user", "MAX_RETRIES"]

MAX_RETRIES = 3
_internal_cache = {}

class UserService:
    """Service for managing users."""

    def __init__(self, db):
        self.db = db

    def get_user(self, user_id: int):
        return self.db.find(user_id)

    @staticmethod
    def validate(data):
        return bool(data)

@decorator
def create_user(name: str, email: str) -> dict:
    """Create a new user."""
    return {"name": name, "email": email}

def _helper():
    pass

async def fetch_data(url: str) -> bytes:
    pass
"#;
        let analyzer = PythonAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"UserService"));
        assert!(names.contains(&"__init__"));
        assert!(names.contains(&"get_user"));
        assert!(names.contains(&"validate"));
        assert!(names.contains(&"create_user"));
        assert!(names.contains(&"_helper"));
        assert!(names.contains(&"fetch_data"));
        assert!(names.contains(&"MAX_RETRIES"));
        assert!(names.contains(&"_internal_cache"));

        let imports = analyzer.extract_imports(source).unwrap();
        assert!(imports.iter().any(|i| i.source == "os"));
        assert!(imports.iter().any(|i| i.source == "sys"));
        assert!(imports.iter().any(|i| i.source == "typing"));
        assert!(imports.iter().any(|i| i.source == "pathlib"));

        let exports = analyzer.extract_exports(source).unwrap();
        let export_names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            export_names,
            vec!["UserService", "create_user", "MAX_RETRIES"]
        );
        assert_eq!(exports[0].kind, SymbolKind::Class);
        assert_eq!(exports[1].kind, SymbolKind::Function);
        assert_eq!(exports[2].kind, SymbolKind::Constant);
    }

    #[test]
    fn dunder_all_names_not_in_symbols_default_to_variable() {
        let source = br#"from .models import User

__all__ = ["User", "helper"]

def helper():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert_eq!(exports.len(), 2);
        // "User" is not in symbols (it's an import), defaults to Variable
        assert_eq!(exports[0].name, "User");
        assert_eq!(exports[0].kind, SymbolKind::Variable);
        // "helper" is in symbols
        assert_eq!(exports[1].name, "helper");
        assert_eq!(exports[1].kind, SymbolKind::Function);
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = br#"import os

def first():
    pass

class Second:
    def method(self):
        pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols[0].name, "first");
        assert_eq!(symbols[0].range.start, 3);
        assert_eq!(symbols[1].name, "Second");
        assert_eq!(symbols[1].range.start, 6);
        assert_eq!(symbols[2].name, "method");
        assert_eq!(symbols[2].range.start, 7);

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports[0].line, 1);
    }

    #[test]
    fn registry_matches_py_and_pyi_files() {
        let registry = super::super::LanguageRegistry::with_defaults();

        let py = registry.analyzer_for_file(Path::new("main.py"));
        assert!(py.is_some());
        assert_eq!(py.unwrap().language_id(), "python");

        let pyi = registry.analyzer_for_file(Path::new("stubs.pyi"));
        assert!(pyi.is_some());
        assert_eq!(pyi.unwrap().language_id(), "python");

        // Not Python
        assert_ne!(
            registry
                .analyzer_for_file(Path::new("lib.rs"))
                .unwrap()
                .language_id(),
            "python"
        );
    }

    #[test]
    fn decorated_methods_in_class() {
        let source = br#"class Service:
    @staticmethod
    def create():
        pass

    @classmethod
    def from_config(cls):
        pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let methods: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Method)
            .collect();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].name, "create");
        assert_eq!(methods[1].name, "from_config");
        // Range includes decorator
        assert!(methods[0].range.start < methods[0].range.end);
    }

    #[test]
    fn parse_cache_returns_consistent_results() {
        let source = br#"def cached():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let first = analyzer.extract_symbols(source).unwrap();
        let second = analyzer.extract_symbols(source).unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0].name, second[0].name);
    }

    #[test]
    fn multiline_from_import() {
        let source = br#"from os.path import (
    join,
    exists,
    dirname as dn,
)
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "os.path");
        assert_eq!(imports[0].symbols.len(), 3);
        assert_eq!(imports[0].symbols[0].name, "join");
        assert_eq!(imports[0].symbols[1].name, "exists");
        assert_eq!(imports[0].symbols[2].name, "dirname");
        assert_eq!(imports[0].symbols[2].alias, Some("dn".to_string()));
    }

    #[test]
    fn dunder_all_is_not_a_symbol() {
        let source = br#"__all__ = ["Foo"]

class Foo:
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(!symbols.iter().any(|s| s.name == "__all__"));
    }

    #[test]
    fn comments_do_not_produce_symbols() {
        let source = br#"# def not_a_function():
#     pass

"""
class NotAClass:
    pass
"""

def real_func():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "real_func");
    }

    // === Stress tests and edge cases ===

    #[test]
    fn large_module_with_many_functions() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("def func_{}(): pass\n", i));
        }
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source.as_bytes()).unwrap();

        let functions: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .collect();
        assert_eq!(functions.len(), 100);
        for i in 0..100 {
            assert!(
                functions.iter().any(|s| s.name == format!("func_{}", i)),
                "missing func_{}",
                i
            );
        }
    }

    #[test]
    fn deeply_nested_classes() {
        let source = b"class A:\n  class B:\n    class C:\n      def deep(self): pass\n";
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        // Top-level class A is extracted
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "A" && s.kind == SymbolKind::Class)
        );
        // Nested classes are not extracted by the current top-level-only walk,
        // but the analyzer does not crash on deeply nested structures.
    }

    #[test]
    fn realistic_fastapi_endpoint() {
        let source = br#"from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

class UserCreate(BaseModel):
    name: str
    email: str
    age: Optional[int] = None

class UserResponse(BaseModel):
    id: int
    name: str
    email: str

@app.post("/users", response_model=UserResponse)
async def create_user(user: UserCreate) -> UserResponse:
    if not user.name:
        raise HTTPException(status_code=400, detail="Name required")
    return UserResponse(id=1, name=user.name, email=user.email)

@app.get("/users/{user_id}")
async def get_user(user_id: int) -> UserResponse:
    return UserResponse(id=user_id, name="test", email="test@test.com")
"#;
        let analyzer = PythonAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"UserCreate"));
        assert!(names.contains(&"UserResponse"));
        assert!(names.contains(&"create_user"));
        assert!(names.contains(&"get_user"));
        assert!(names.contains(&"app"));

        let imports = analyzer.extract_imports(source).unwrap();
        assert!(imports.iter().any(|i| i.source == "fastapi"
            && i.symbols.iter().any(|s| s.name == "FastAPI")
            && i.symbols.iter().any(|s| s.name == "HTTPException")));
        assert!(
            imports
                .iter()
                .any(|i| i.source == "pydantic" && i.symbols.iter().any(|s| s.name == "BaseModel"))
        );
        assert!(
            imports
                .iter()
                .any(|i| i.source == "typing" && i.symbols.iter().any(|s| s.name == "Optional"))
        );
    }

    #[test]
    fn async_generators_and_comprehensions() {
        let source = br#"async def gen():
    async for x in some_iter():
        yield x

def comprehensions():
    squares = [x**2 for x in range(10)]
    evens = {x for x in range(20) if x % 2 == 0}
    mapping = {k: v for k, v in items()}
    return squares, evens, mapping
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "gen" && s.kind == SymbolKind::Function)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "comprehensions" && s.kind == SymbolKind::Function)
        );
    }

    #[test]
    fn decorator_stacking() {
        let source = br#"@auth_required
@rate_limit(100)
@cache(ttl=300)
@log_calls
def protected_endpoint(request):
    return {"ok": True}
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "protected_endpoint");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        // Range starts at the first decorator
        assert_eq!(symbols[0].range.start, 1);
        assert!(
            symbols[0]
                .signature
                .as_ref()
                .unwrap()
                .contains("def protected_endpoint")
        );
    }

    #[test]
    fn star_imports_and_relative_imports() {
        let source = br#"from . import foo
from ..bar import baz
from ...deep.pkg import something
from module import *
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 4);

        // from . import foo
        assert_eq!(imports[0].source, ".");
        assert_eq!(imports[0].symbols[0].name, "foo");

        // from ..bar import baz
        assert_eq!(imports[1].source, "..bar");
        assert_eq!(imports[1].symbols[0].name, "baz");

        // from ...deep.pkg import something
        assert_eq!(imports[2].source, "...deep.pkg");
        assert_eq!(imports[2].symbols[0].name, "something");

        // from module import *
        assert_eq!(imports[3].source, "module");
        assert_eq!(imports[3].symbols[0].name, "*");
    }

    #[test]
    fn walrus_operator_and_match_statement() {
        let source = br#"def uses_walrus(data):
    if (n := len(data)) > 10:
        return n
    return 0

def uses_match(command):
    match command:
        case "quit":
            return False
        case "help":
            print("help text")
        case _:
            pass
    return True
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "uses_walrus");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert_eq!(symbols[1].name, "uses_match");
        assert_eq!(symbols[1].kind, SymbolKind::Function);

        // Imports and exports also succeed without crashing
        assert!(analyzer.extract_imports(source).unwrap().is_empty());
        assert_eq!(analyzer.extract_exports(source).unwrap().len(), 2);
    }

    #[test]
    fn language_id_and_file_extensions() {
        let analyzer = PythonAnalyzer::new();
        assert_eq!(analyzer.language_id(), "python");
        assert_eq!(analyzer.file_extensions(), &["py", "pyi"]);
    }

    #[test]
    fn constants_reject_mixed_case() {
        let source = br#"MixedCase = 42
VALID_CONST = 1
lowercase = 2
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let mixed = symbols.iter().find(|s| s.name == "MixedCase").unwrap();
        assert_eq!(
            mixed.kind,
            SymbolKind::Variable,
            "MixedCase should be Variable, not Constant"
        );

        let valid = symbols.iter().find(|s| s.name == "VALID_CONST").unwrap();
        assert_eq!(valid.kind, SymbolKind::Constant);

        let lower = symbols.iter().find(|s| s.name == "lowercase").unwrap();
        assert_eq!(lower.kind, SymbolKind::Variable);
    }

    #[test]
    fn dunder_all_ignores_other_assignments() {
        let source = br#"ITEMS = ["a", "b"]

__all__ = ["MyClass"]

class MyClass:
    pass

def helper():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        // Only __all__ should control exports, not ITEMS
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "MyClass");
    }

    #[test]
    fn import_statement_line_numbers() {
        let source = br#"import os

x = 1

import sys
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "os");
        assert_eq!(imports[0].line, 1);
        assert_eq!(imports[1].source, "sys");
        assert_eq!(imports[1].line, 5);
    }

    #[test]
    fn range_start_and_end_for_all_symbol_kinds() {
        let source = br#"def top_func():
    pass

class MyClass:
    def method(self):
        pass

MAX_SIZE = 1024

name = "grove"

@decorator
def decorated():
    pass
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let top_func = symbols.iter().find(|s| s.name == "top_func").unwrap();
        assert_eq!(top_func.range.start, 1);
        assert_eq!(top_func.range.end, 2);

        let my_class = symbols.iter().find(|s| s.name == "MyClass").unwrap();
        assert_eq!(my_class.range.start, 4);
        assert_eq!(my_class.range.end, 6);

        let method = symbols.iter().find(|s| s.name == "method").unwrap();
        assert_eq!(method.range.start, 5);
        assert_eq!(method.range.end, 6);

        let max_size = symbols.iter().find(|s| s.name == "MAX_SIZE").unwrap();
        assert_eq!(max_size.range.start, 8);
        assert_eq!(max_size.range.end, 8);

        let name_var = symbols.iter().find(|s| s.name == "name").unwrap();
        assert_eq!(name_var.range.start, 10);
        assert_eq!(name_var.range.end, 10);

        let decorated = symbols.iter().find(|s| s.name == "decorated").unwrap();
        assert_eq!(decorated.range.start, 12);
        assert_eq!(decorated.range.end, 14);
    }

    // === Mutant-killing tests ===

    #[test]
    fn parse_cache_invalidates_when_source_changes() {
        // Kills mutant on line 40: replace == with != in PythonAnalyzer::parse
        // If the cache equality is inverted, parsing different source would
        // incorrectly return stale cached results.
        let analyzer = PythonAnalyzer::new();

        let source_a = b"def alpha():\n    pass\n";
        let source_b = b"def beta():\n    pass\n";

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
    fn decorated_method_exact_range_start_and_end() {
        // Kills mutants on lines 311-312:
        //   311: replace + with - in extract_method (end line)
        //   311: replace + with * in extract_method (end line)
        //   312: replace + with * in extract_method (start line)
        // The decorated_definition node spans from the decorator to the end
        // of the method body. We place the decorated method on rows > 0 so
        // that row + 1 != row * 1 and row + 1 != row - 1.
        let source = br#"class Service:
    pass

class Api:
    @staticmethod
    def create(data):
        validated = True
        return validated

    @classmethod
    def from_env(cls):
        return cls()
"#;
        let analyzer = PythonAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        // "create" decorated method: decorator @staticmethod is on line 5 (row 4),
        // method body ends on line 8 (row 7)
        let create = symbols.iter().find(|s| s.name == "create").unwrap();
        assert_eq!(create.kind, SymbolKind::Method);
        assert_eq!(
            create.range.start, 5,
            "decorated method start should be line 5 (decorator line)"
        );
        assert_eq!(
            create.range.end, 8,
            "decorated method end should be line 8 (last line of body)"
        );

        // "from_env" decorated method: decorator @classmethod is on line 10 (row 9),
        // method body ends on line 12 (row 11)
        let from_env = symbols.iter().find(|s| s.name == "from_env").unwrap();
        assert_eq!(from_env.kind, SymbolKind::Method);
        assert_eq!(
            from_env.range.start, 10,
            "decorated method start should be line 10 (decorator line)"
        );
        assert_eq!(
            from_env.range.end, 12,
            "decorated method end should be line 12 (last line of body)"
        );
    }

    #[test]
    fn import_statement_line_numbers_on_later_lines() {
        // Kills mutants on line 354:
        //   354: replace + with - in extract_import_statement (aliased_import line)
        //   354: replace + with * in extract_import_statement (aliased_import line)
        // Place `import X as Y` on a line with row > 1 so row + 1 != row * 1
        // and row + 1 != row - 1.
        let source = br#"x = 1
y = 2
z = 3
import os.path as osp
import json as j
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        // `import os.path as osp` is on line 4 (row 3)
        assert_eq!(imports[0].source, "os.path");
        assert_eq!(
            imports[0].line, 4,
            "aliased import should be on line 4, got {}",
            imports[0].line
        );
        // `import json as j` is on line 5 (row 4)
        assert_eq!(imports[1].source, "json");
        assert_eq!(
            imports[1].line, 5,
            "aliased import should be on line 5, got {}",
            imports[1].line
        );
    }

    #[test]
    fn wildcard_import_line_number_on_later_line() {
        // Kills mutants on line 385:
        //   385: replace + with * in extract_import_from_statement (wildcard line)
        // Place `from X import *` on a line with row > 1 so row + 1 != row * 1.
        let source = br#"x = 1
y = 2
z = 3
from os import *
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "os");
        assert_eq!(imports[0].symbols[0].name, "*");
        assert_eq!(
            imports[0].line, 4,
            "wildcard import should be on line 4, got {}",
            imports[0].line
        );
    }

    #[test]
    fn from_import_line_number_on_later_line() {
        // Kills mutants on line 419:
        //   419: replace + with * in extract_import_from_statement (named import line)
        // Place `from X import Y` on a line with row > 1 so row + 1 != row * 1.
        let source = br#"x = 1
y = 2
z = 3
from os.path import join, exists
from typing import List
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        // `from os.path import join, exists` is on line 4 (row 3)
        assert_eq!(imports[0].source, "os.path");
        assert_eq!(
            imports[0].line, 4,
            "from import should be on line 4, got {}",
            imports[0].line
        );
        // `from typing import List` is on line 5 (row 4)
        assert_eq!(imports[1].source, "typing");
        assert_eq!(
            imports[1].line, 5,
            "from import should be on line 5, got {}",
            imports[1].line
        );
    }

    #[test]
    fn dotted_import_line_number_on_later_line() {
        // Additional coverage for line 334 in extract_import_statement:
        // `import X` (dotted_name) on a later line ensures row + 1 != row * 1.
        let source = br#"x = 1
y = 2
import collections
import pathlib
"#;
        let analyzer = PythonAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "collections");
        assert_eq!(
            imports[0].line, 3,
            "dotted import should be on line 3, got {}",
            imports[0].line
        );
        assert_eq!(imports[1].source, "pathlib");
        assert_eq!(
            imports[1].line, 4,
            "dotted import should be on line 4, got {}",
            imports[1].line
        );
    }
}
