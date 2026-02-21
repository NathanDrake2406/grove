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
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
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

fn extract_field_names(node: tree_sitter::Node<'_>, source: &[u8], symbols: &mut Vec<Symbol>) {
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

fn flatten_scoped_identifier(node: tree_sitter::Node<'_>, source: &[u8], parts: &mut Vec<String>) {
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

    fn is_schema_file(&self, path: &Path) -> bool {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        matches!(
            filename.as_str(),
            "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "settings.gradle"
                | "settings.gradle.kts"
                | "gradle.properties"
        )
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

        assert!(symbols
            .iter()
            .any(|s| s.name == "UserService" && s.kind == SymbolKind::Class));
        assert!(symbols
            .iter()
            .any(|s| s.name == "createUser" && s.kind == SymbolKind::Method));
        assert!(symbols
            .iter()
            .any(|s| s.name == "Repository" && s.kind == SymbolKind::Interface));
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

        assert!(symbols
            .iter()
            .any(|s| s.name == "Color" && s.kind == SymbolKind::Enum));
        assert!(symbols
            .iter()
            .any(|s| s.name == "Point" && s.kind == SymbolKind::Class));
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

        assert!(symbols
            .iter()
            .any(|s| s.name == "User" && s.kind == SymbolKind::Class));
        assert!(symbols
            .iter()
            .any(|s| s.name == "User" && s.kind == SymbolKind::Method)); // constructor
        assert!(symbols
            .iter()
            .any(|s| s.name == "name" && s.kind == SymbolKind::Variable));
        assert!(symbols
            .iter()
            .any(|s| s.name == "age" && s.kind == SymbolKind::Variable));
    }

    #[test]
    fn extracts_annotation_type() {
        let source = br#"
public @interface MyAnnotation {
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols
            .iter()
            .any(|s| s.name == "MyAnnotation" && s.kind == SymbolKind::Interface));
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
    fn flattens_multilevel_import_path() {
        let source = br#"
import java.util.Map.Entry;
"#;
        let analyzer = JavaAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "java.util.Map.Entry");
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
    fn exports_public_constant_and_omits_private_constant() {
        let source = br#"
public class Config {
    public static final String API_VERSION = "v1";
    private static final String SECRET_KEY = "internal";
}
"#;
        let analyzer = JavaAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "API_VERSION"));
        assert!(symbols.iter().any(|s| s.name == "SECRET_KEY"));

        let exports = analyzer.extract_exports(source).unwrap();
        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Config"));
        assert!(names.contains(&"API_VERSION"));
        assert!(!names.contains(&"SECRET_KEY"));
    }

    #[test]
    fn exports_nested_public_static_class_and_public_method() {
        let source = br#"
public class Outer {
    public static class Inner {
        public void exposed() {}
    }

    private static class Hidden {}
}
"#;
        let analyzer = JavaAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Outer"));
        assert!(names.contains(&"Inner"));
        assert!(names.contains(&"exposed"));
        assert!(!names.contains(&"Hidden"));
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

    #[test]
    fn schema_file_detection() {
        let analyzer = JavaAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("pom.xml")));
        assert!(analyzer.is_schema_file(Path::new("build.gradle")));
        assert!(analyzer.is_schema_file(Path::new("build.gradle.kts")));
        assert!(analyzer.is_schema_file(Path::new("settings.gradle")));
        assert!(analyzer.is_schema_file(Path::new("settings.gradle.kts")));
        assert!(analyzer.is_schema_file(Path::new("gradle.properties")));
        assert!(analyzer.is_schema_file(Path::new("myproject/pom.xml")));
        assert!(!analyzer.is_schema_file(Path::new("Main.java")));
        assert!(!analyzer.is_schema_file(Path::new("pom.xml.bak")));
    }

    // === Stress tests and edge cases ===

    #[test]
    fn empty_source_returns_empty() {
        let analyzer = JavaAnalyzer::new();
        assert!(analyzer.extract_symbols(b"").unwrap().is_empty());
        assert!(analyzer.extract_imports(b"").unwrap().is_empty());
        assert!(analyzer.extract_exports(b"").unwrap().is_empty());
    }

    #[test]
    fn malformed_source_recovers() {
        let source = br#"
public class Stable {
    public void stableMethod() {}
}

public class Broken {
    public void brokenMethod( {
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "Stable"));
        assert!(symbols.iter().any(|s| s.name == "stableMethod"));
    }

    #[test]
    fn nested_classes_extracted() {
        let source = br#"
public class Outer {
    public class Inner {
        public void innerMethod() {}
    }
    private static class StaticNested {}
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols
            .iter()
            .any(|s| s.name == "Outer" && s.kind == SymbolKind::Class));
        assert!(symbols
            .iter()
            .any(|s| s.name == "Inner" && s.kind == SymbolKind::Class));
        assert!(symbols
            .iter()
            .any(|s| s.name == "innerMethod" && s.kind == SymbolKind::Method));
        assert!(symbols
            .iter()
            .any(|s| s.name == "StaticNested" && s.kind == SymbolKind::Class));
    }

    #[test]
    fn generic_class_extracted() {
        let source = br#"
public class Box<T> {
    private T value;
    public T getValue() { return value; }
}

public interface Comparable<T> {
    int compareTo(T other);
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(symbols
            .iter()
            .any(|s| s.name == "Box" && s.kind == SymbolKind::Class));
        assert!(symbols
            .iter()
            .any(|s| s.name == "getValue" && s.kind == SymbolKind::Method));
        assert!(symbols
            .iter()
            .any(|s| s.name == "Comparable" && s.kind == SymbolKind::Interface));
    }

    #[test]
    fn realistic_spring_controller() {
        let source = br#"
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;

@RestController
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/users")
    public List<User> getUsers() {
        return userService.findAll();
    }

    @PostMapping("/users")
    public User createUser(User user) {
        return userService.save(user);
    }

    private void validateUser(User user) {
        // internal validation
    }
}
"#;
        let analyzer = JavaAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "UserController"));
        assert!(symbols.iter().any(|s| s.name == "getUsers"));
        assert!(symbols.iter().any(|s| s.name == "createUser"));
        assert!(symbols.iter().any(|s| s.name == "validateUser"));
        assert!(symbols
            .iter()
            .any(|s| s.name == "userService" && s.kind == SymbolKind::Variable));

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 5);
        assert!(imports
            .iter()
            .any(|i| i.source == "org.springframework.web.bind.annotation.RestController"));
        assert!(imports.iter().any(|i| i.source == "java.util.List"));

        let exports = analyzer.extract_exports(source).unwrap();
        let export_names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(export_names.contains(&"UserController"));
        assert!(export_names.contains(&"getUsers"));
        assert!(export_names.contains(&"createUser"));
        assert!(!export_names.contains(&"validateUser"));
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = br#"import java.util.List;

public class Main {
    public void first() {}

    public void second() {}
}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let first = symbols.iter().find(|s| s.name == "first").unwrap();
        assert_eq!(first.range.start, 4);
        let second = symbols.iter().find(|s| s.name == "second").unwrap();
        assert_eq!(second.range.start, 6);

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports[0].line, 1);
    }

    #[test]
    fn registry_matches_java_files() {
        let registry = super::super::LanguageRegistry::with_defaults();
        let analyzer = registry.analyzer_for_file(Path::new("Main.java"));
        assert!(analyzer.is_some());
        assert_eq!(analyzer.unwrap().language_id(), "java");

        assert!(registry
            .analyzer_for_file(Path::new("src/com/example/Service.java"))
            .is_some());
        assert_ne!(
            registry
                .analyzer_for_file(Path::new("lib.rs"))
                .unwrap()
                .language_id(),
            "java"
        );
    }

    #[test]
    fn parse_cache_returns_consistent_results() {
        let source = br#"
public class Cached {
    public void method() {}
}
"#;
        let analyzer = JavaAnalyzer::new();
        let first = analyzer.extract_symbols(source).unwrap();
        let second = analyzer.extract_symbols(source).unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0].name, second[0].name);
    }

    #[test]
    fn comments_do_not_produce_symbols() {
        let source = br#"
// public class NotAClass {}
/* public interface NotAnInterface {} */

public class RealClass {}
"#;
        let analyzer = JavaAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "RealClass");
    }
}
