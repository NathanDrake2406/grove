use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

struct ParseCache {
    source: Vec<u8>,
    tree: tree_sitter::Tree,
}

pub struct JavaAnalyzer {
    parser: std::sync::Mutex<Parser>,
    parse_cache: std::sync::Mutex<Option<ParseCache>>,
}

impl Default for JavaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl JavaAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("failed to set java language");
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
                .ok_or_else(|| AnalysisError::ParseError("java parse failed".into()))?
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

fn collect_symbols(node: tree_sitter::Node<'_>, source: &[u8], symbols: &mut Vec<Symbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Class,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_symbols(body, source, symbols);
                }
            }
            "interface_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Interface,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_symbols(body, source, symbols);
                }
            }
            "enum_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Enum,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_symbols(body, source, symbols);
                }
            }
            "record_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Class,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_symbols(body, source, symbols);
                }
            }
            "annotation_type_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Interface,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
            "method_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Method,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: Some(get_signature_line(source, child.start_byte())),
                    });
                }
            }
            "constructor_declaration" => {
                if let Some(name) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Method,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: Some(get_signature_line(source, child.start_byte())),
                    });
                }
            }
            "field_declaration" | "constant_declaration" => {
                extract_field_names(child, source, symbols);
            }
            _ => {}
        }
    }
}

fn extract_field_names(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    symbols: &mut Vec<Symbol>,
) {
    let kind = if node.kind() == "constant_declaration" {
        SymbolKind::Constant
    } else {
        SymbolKind::Variable
    };

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "variable_declarator" {
            if let Some(name) = child.child_by_field_name("name") {
                symbols.push(Symbol {
                    name: name.utf8_text(source).unwrap_or("").to_string(),
                    kind,
                    range: LineRange {
                        start: node.start_position().row as u32 + 1,
                        end: node.end_position().row as u32 + 1,
                    },
                    signature: None,
                });
            }
        }
    }
}

fn has_public_modifier(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "modifiers" {
            let mut mod_cursor = child.walk();
            for modifier in child.children(&mut mod_cursor) {
                if modifier.utf8_text(source).unwrap_or("") == "public" {
                    return true;
                }
            }
        }
    }
    false
}

fn collect_exports(node: tree_sitter::Node<'_>, source: &[u8], exports: &mut Vec<ExportedSymbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "class_declaration" | "record_declaration" => {
                if has_public_modifier(child, source) {
                    if let Some(name) = child.child_by_field_name("name") {
                        exports.push(ExportedSymbol {
                            name: name.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Class,
                            signature: None,
                        });
                    }
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_exports(body, source, exports);
                }
            }
            "interface_declaration" | "annotation_type_declaration" => {
                if has_public_modifier(child, source) {
                    if let Some(name) = child.child_by_field_name("name") {
                        exports.push(ExportedSymbol {
                            name: name.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Interface,
                            signature: None,
                        });
                    }
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_exports(body, source, exports);
                }
            }
            "enum_declaration" => {
                if has_public_modifier(child, source) {
                    if let Some(name) = child.child_by_field_name("name") {
                        exports.push(ExportedSymbol {
                            name: name.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Enum,
                            signature: None,
                        });
                    }
                }
                if let Some(body) = child.child_by_field_name("body") {
                    collect_exports(body, source, exports);
                }
            }
            "method_declaration" | "constructor_declaration" => {
                if has_public_modifier(child, source) {
                    if let Some(name) = child.child_by_field_name("name") {
                        exports.push(ExportedSymbol {
                            name: name.utf8_text(source).unwrap_or("").to_string(),
                            kind: SymbolKind::Method,
                            signature: Some(get_signature_line(source, child.start_byte())),
                        });
                    }
                }
            }
            "field_declaration" | "constant_declaration" => {
                if has_public_modifier(child, source) {
                    let kind = if child.kind() == "constant_declaration" {
                        SymbolKind::Constant
                    } else {
                        SymbolKind::Variable
                    };
                    let mut field_cursor = child.walk();
                    for field_child in child.children(&mut field_cursor) {
                        if field_child.kind() == "variable_declarator" {
                            if let Some(name) = field_child.child_by_field_name("name") {
                                exports.push(ExportedSymbol {
                                    name: name.utf8_text(source).unwrap_or("").to_string(),
                                    kind,
                                    signature: None,
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn flatten_scoped_identifier(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    parts: &mut Vec<String>,
) {
    if node.kind() == "identifier" {
        parts.push(node.utf8_text(source).unwrap_or("").to_string());
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "scoped_identifier" | "identifier" => {
                flatten_scoped_identifier(child, source, parts);
            }
            _ => {}
        }
    }
}

impl LanguageAnalyzer for JavaAnalyzer {
    fn language_id(&self) -> &str {
        "java"
    }

    fn file_extensions(&self) -> &[&str] {
        &["java"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        collect_symbols(root, source, &mut symbols);
        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "import_declaration" {
                let mut path_parts = Vec::new();
                let mut has_wildcard = false;

                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    match inner.kind() {
                        "scoped_identifier" | "identifier" => {
                            flatten_scoped_identifier(inner, source, &mut path_parts);
                        }
                        "asterisk" => {
                            has_wildcard = true;
                        }
                        _ => {}
                    }
                }

                if !path_parts.is_empty() {
                    let mut path = path_parts.join(".");
                    if has_wildcard {
                        path.push_str(".*");
                    }
                    imports.push(Import {
                        source: path,
                        symbols: vec![],
                        line: child.start_position().row as u32 + 1,
                    });
                }
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        collect_exports(root, source, &mut exports);
        Ok(exports)
    }

    fn is_schema_file(&self, _path: &Path) -> bool {
        false // stub — tests will fail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_class_and_interface_symbols() {
        let source = br#"
public class UserService {
    public void createUser(String name) {}
}

interface Repository {
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols.iter().any(|s| s.name == "UserService" && s.kind == SymbolKind::Class));
        assert!(symbols.iter().any(|s| s.name == "createUser" && s.kind == SymbolKind::Method));
        assert!(symbols.iter().any(|s| s.name == "Repository" && s.kind == SymbolKind::Interface));
    }

    #[test]
    fn extracts_enum_and_record() {
        let source = br#"
enum Color {
    RED, GREEN, BLUE
}

public record Point(int x, int y) {
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols.iter().any(|s| s.name == "Color" && s.kind == SymbolKind::Enum));
        assert!(symbols.iter().any(|s| s.name == "Point" && s.kind == SymbolKind::Class));
    }

    #[test]
    fn extracts_constructor_and_field() {
        let source = br#"
public class User {
    private String name;
    private int age;

    public User(String name, int age) {
        this.name = name;
        this.age = age;
    }
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols.iter().any(|s| s.name == "User" && s.kind == SymbolKind::Class));
        assert!(symbols.iter().any(|s| s.name == "User" && s.kind == SymbolKind::Method)); // constructor
        assert!(symbols.iter().any(|s| s.name == "name" && s.kind == SymbolKind::Variable));
        assert!(symbols.iter().any(|s| s.name == "age" && s.kind == SymbolKind::Variable));
    }

    #[test]
    fn extracts_annotation_type() {
        let source = br#"
public @interface MyAnnotation {
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols.iter().any(|s| s.name == "MyAnnotation" && s.kind == SymbolKind::Interface));
    }

    #[test]
    fn extracts_method_signature() {
        let source = br#"
public class Calc {
    public int add(int a, int b) {
        return a + b;
    }
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let method = symbols.iter().find(|s| s.name == "add").unwrap();
        assert!(method.signature.as_ref().unwrap().contains("add"));
        assert!(method.signature.as_ref().unwrap().contains("int"));
    }

    #[test]
    fn extracts_single_import() {
        let source = br#"
import java.util.List;
"#;
        let analyzer = JavaAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "java.util.List");
    }

    #[test]
    fn extracts_wildcard_import() {
        let source = br#"
import java.util.*;
"#;
        let analyzer = JavaAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "java.util.*");
    }

    #[test]
    fn extracts_static_import() {
        let source = br#"
import static org.junit.Assert.assertEquals;
import static java.util.Collections.*;
"#;
        let analyzer = JavaAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "org.junit.Assert.assertEquals");
        assert_eq!(imports[1].source, "java.util.Collections.*");
    }

    #[test]
    fn extracts_multiple_imports() {
        let source = br#"
import java.util.List;
import java.util.Map;
import java.io.IOException;
"#;
        let analyzer = JavaAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].source, "java.util.List");
        assert_eq!(imports[1].source, "java.util.Map");
        assert_eq!(imports[2].source, "java.io.IOException");
    }

    #[test]
    fn exports_only_public_symbols() {
        let source = br#"
public class UserService {
    public void createUser(String name) {}
    private void validate(String name) {}
    void helper() {}
}

class InternalHelper {
}
"#;
        let analyzer = JavaAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"UserService"));
        assert!(names.contains(&"createUser"));
        assert!(!names.contains(&"validate"));
        assert!(!names.contains(&"helper"));
        assert!(!names.contains(&"InternalHelper"));
    }

    #[test]
    fn public_interface_is_exported() {
        let source = br#"
public interface Repository {
    void save(Object entity);
}
"#;
        let analyzer = JavaAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert!(exports.iter().any(|e| e.name == "Repository"));
    }
}
