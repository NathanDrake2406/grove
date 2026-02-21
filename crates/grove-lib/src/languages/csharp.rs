use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

struct ParseCache {
    source: Vec<u8>,
    tree: tree_sitter::Tree,
}

pub struct CSharpAnalyzer {
    parser: std::sync::Mutex<Parser>,
    parse_cache: std::sync::Mutex<Option<ParseCache>>,
}

impl Default for CSharpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl CSharpAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("failed to set C# language");
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
                .ok_or_else(|| AnalysisError::ParseError("C# parse failed".into()))?
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
    text.lines().next().unwrap_or("").trim().to_string()
}

/// Check whether a record_declaration has a `struct` keyword child,
/// making it a `record struct` rather than a plain `record` (class).
fn is_record_struct(node: tree_sitter::Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "struct")
}

/// Recursively extract declarations from the AST, descending into
/// namespaces and type bodies.
fn extract_declarations(node: tree_sitter::Node<'_>, source: &[u8], symbols: &mut Vec<Symbol>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                // Descend into namespace body
                let mut ns_cursor = child.walk();
                for ns_child in child.children(&mut ns_cursor) {
                    if ns_child.kind() == "declaration_list" {
                        extract_declarations(ns_child, source, symbols);
                    }
                }
                // file_scoped_namespace declarations put children directly
                // after the semicolon at the same level
                if child.kind() == "file_scoped_namespace_declaration" {
                    extract_declarations(child, source, symbols);
                }
            }
            "class_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Class,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                // Descend into class body
                if let Some(body) = child.child_by_field_name("body") {
                    extract_declarations(body, source, symbols);
                }
            }
            "struct_declaration" => {
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
                if let Some(body) = child.child_by_field_name("body") {
                    extract_declarations(body, source, symbols);
                }
            }
            "interface_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Interface,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    extract_declarations(body, source, symbols);
                }
            }
            "enum_declaration" => {
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
                // No descent — enum members aren't useful for overlap detection
            }
            "record_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let kind = if is_record_struct(child) {
                        SymbolKind::Struct
                    } else {
                        SymbolKind::Class
                    };
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
                if let Some(body) = child.child_by_field_name("body") {
                    extract_declarations(body, source, symbols);
                }
            }
            "method_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
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
                if let Some(name_node) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Method,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: Some(get_signature_line(source, child.start_byte())),
                    });
                }
            }
            "property_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Variable,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
            "field_declaration" => {
                extract_field_symbols(child, source, symbols);
            }
            _ => {}
        }
    }
}

/// Extract variable names from a field_declaration node.
/// Structure: field_declaration → variable_declaration → variable_declarator → identifier
fn extract_field_symbols(field: tree_sitter::Node<'_>, source: &[u8], symbols: &mut Vec<Symbol>) {
    let mut cursor = field.walk();
    for child in field.children(&mut cursor) {
        if child.kind() == "variable_declaration" {
            let mut var_cursor = child.walk();
            for var_child in child.children(&mut var_cursor) {
                if var_child.kind() == "variable_declarator"
                    && let Some(name_node) = var_child.child_by_field_name("name")
                {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Variable,
                        range: LineRange {
                            start: field.start_position().row as u32 + 1,
                            end: field.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
        }
    }
}

/// Recursively collect using directives from the AST.
/// Handles top-level usings and usings inside namespace bodies.
fn collect_using_directives(node: tree_sitter::Node<'_>, source: &[u8], imports: &mut Vec<Import>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "using_directive" => {
                if let Some(import) = parse_using_directive(child, source) {
                    imports.push(import);
                }
            }
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                // Descend into namespace body to find nested usings
                let mut ns_cursor = child.walk();
                for ns_child in child.children(&mut ns_cursor) {
                    if ns_child.kind() == "declaration_list" {
                        collect_using_directives(ns_child, source, imports);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Parse a single using_directive node into an Import.
///
/// Handles three forms:
/// - `using System;` → source = "System"
/// - `using Json = System.Text.Json;` → source = "System.Text.Json", symbol = "Json"
/// - `using static System.Math;` → source = "System.Math"
fn parse_using_directive(node: tree_sitter::Node<'_>, source: &[u8]) -> Option<Import> {
    let line = node.start_position().row as u32 + 1;
    let mut has_equals = false;
    let mut has_static = false;
    let mut alias_name: Option<String> = None;
    let mut namespace_source: Option<String> = None;

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "static" => {
                has_static = true;
            }
            "=" => {
                has_equals = true;
            }
            "identifier" => {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                if has_equals {
                    // identifier after = is a simple namespace (no dots)
                    namespace_source = Some(text);
                } else if !has_static && namespace_source.is_none() {
                    // First identifier before = could be alias or simple namespace
                    if alias_name.is_none() {
                        alias_name = Some(text);
                    }
                } else {
                    namespace_source = Some(text);
                }
            }
            "qualified_name" => {
                let text = child.utf8_text(source).unwrap_or("").to_string();
                namespace_source = Some(text);
            }
            _ => {}
        }
    }

    // Determine the final source and symbols
    if has_equals {
        // Aliased: `using Alias = Namespace;`
        let ns = namespace_source?;
        let alias = alias_name?;
        Some(Import {
            source: ns,
            symbols: vec![ImportedSymbol {
                name: alias,
                alias: None,
            }],
            line,
        })
    } else if let Some(ns) = namespace_source {
        // `using static Namespace;` or `using QualifiedNamespace;`
        Some(Import {
            source: ns,
            symbols: vec![],
            line,
        })
    } else {
        // `using SimpleIdentifier;` (no dots)
        alias_name.map(|simple| Import {
            source: simple,
            symbols: vec![],
            line,
        })
    }
}

/// Check whether a declaration node has a `public` modifier.
fn has_public_modifier(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| {
        child.kind() == "modifier" && child.utf8_text(source).unwrap_or("") == "public"
    })
}

/// Recursively extract public declarations as exported symbols.
fn extract_public_declarations(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    exports: &mut Vec<ExportedSymbol>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "namespace_declaration" | "file_scoped_namespace_declaration" => {
                let mut ns_cursor = child.walk();
                for ns_child in child.children(&mut ns_cursor) {
                    if ns_child.kind() == "declaration_list" {
                        extract_public_declarations(ns_child, source, exports);
                    }
                }
                if child.kind() == "file_scoped_namespace_declaration" {
                    extract_public_declarations(child, source, exports);
                }
            }
            "class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration" => {
                if has_public_modifier(child, source)
                    && let Some(name_node) = child.child_by_field_name("name")
                {
                    let kind = match child.kind() {
                        "class_declaration" => SymbolKind::Class,
                        "struct_declaration" => SymbolKind::Struct,
                        "interface_declaration" => SymbolKind::Interface,
                        "enum_declaration" => SymbolKind::Enum,
                        "record_declaration" => {
                            if is_record_struct(child) {
                                SymbolKind::Struct
                            } else {
                                SymbolKind::Class
                            }
                        }
                        _ => SymbolKind::Class,
                    };
                    exports.push(ExportedSymbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind,
                        signature: None,
                    });
                }
                // Descend into body for public members
                if let Some(body) = child.child_by_field_name("body") {
                    extract_public_declarations(body, source, exports);
                }
            }
            "method_declaration" | "constructor_declaration" => {
                if has_public_modifier(child, source)
                    && let Some(name_node) = child.child_by_field_name("name")
                {
                    exports.push(ExportedSymbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Method,
                        signature: Some(get_signature_line(source, child.start_byte())),
                    });
                }
            }
            "property_declaration" => {
                if has_public_modifier(child, source)
                    && let Some(name_node) = child.child_by_field_name("name")
                {
                    exports.push(ExportedSymbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::Variable,
                        signature: None,
                    });
                }
            }
            "field_declaration" => {
                if has_public_modifier(child, source) {
                    let mut fc = child.walk();
                    for fc_child in child.children(&mut fc) {
                        if fc_child.kind() == "variable_declaration" {
                            let mut vc = fc_child.walk();
                            for vc_child in fc_child.children(&mut vc) {
                                if vc_child.kind() == "variable_declarator"
                                    && let Some(name_node) = vc_child.child_by_field_name("name")
                                {
                                    exports.push(ExportedSymbol {
                                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                                        kind: SymbolKind::Variable,
                                        signature: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

impl LanguageAnalyzer for CSharpAnalyzer {
    fn language_id(&self) -> &str {
        "csharp"
    }

    fn file_extensions(&self) -> &[&str] {
        &["cs"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        if source.is_empty() {
            return Ok(Vec::new());
        }
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        extract_declarations(root, source, &mut symbols);
        Ok(symbols)
    }

    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        if source.is_empty() {
            return Ok(Vec::new());
        }
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        collect_using_directives(root, source, &mut imports);
        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        if source.is_empty() {
            return Ok(Vec::new());
        }
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        extract_public_declarations(root, source, &mut exports);
        Ok(exports)
    }

    fn is_schema_file(&self, path: &Path) -> bool {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();
        matches!(
            filename.as_str(),
            "Directory.Build.props" | "Directory.Build.targets" | "global.json" | "nuget.config"
        ) || filename.ends_with(".csproj")
            || filename.ends_with(".sln")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_class_and_struct_symbols() {
        let source = br#"
namespace MyApp {
    public class UserService {
    }

    public struct Point {
    }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "UserService" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Point" && s.kind == SymbolKind::Struct)
        );
    }

    #[test]
    fn extracts_interface_and_enum_symbols() {
        let source = br#"
public interface IRepository {
    void Save();
}

public enum Status {
    Active,
    Inactive
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "IRepository" && s.kind == SymbolKind::Interface)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Status" && s.kind == SymbolKind::Enum)
        );
    }

    #[test]
    fn extracts_record_declarations() {
        let source = br#"
public record Person(string FirstName, string LastName);

public record struct Measurement(double Value, string Unit);
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Person" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Measurement" && s.kind == SymbolKind::Struct)
        );
    }

    #[test]
    fn file_scoped_namespace_symbols_are_found() {
        let source = br#"
namespace MyApp.Core;

public class Worker {
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Worker" && s.kind == SymbolKind::Class)
        );
    }

    #[test]
    fn extracts_methods_and_constructors() {
        let source = br#"
public class Service {
    public Service(int id) { }
    public void Process() { }
    private int Calculate(int x) { return x; }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Service" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Service" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Process" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Calculate" && s.kind == SymbolKind::Method)
        );
    }

    #[test]
    fn method_and_constructor_signature_lines_are_tracked() {
        let source = br#"
public class Service {
    public Service(
        int id
    ) { }

    private int Calculate(
        int x
    ) {
        return x;
    }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let constructor = symbols
            .iter()
            .find(|s| s.name == "Service" && s.kind == SymbolKind::Method)
            .unwrap();
        let method = symbols
            .iter()
            .find(|s| s.name == "Calculate" && s.kind == SymbolKind::Method)
            .unwrap();

        assert_eq!(constructor.signature.as_deref(), Some("public Service("));
        assert_eq!(method.signature.as_deref(), Some("private int Calculate("));
    }

    #[test]
    fn extracts_properties_and_fields() {
        let source = br#"
public class Config {
    public string Name { get; set; }
    private int _count;
    public static readonly string Version = "1.0";
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Name" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_count" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Version" && s.kind == SymbolKind::Variable)
        );
    }

    #[test]
    fn multi_variable_field_declaration_yields_each_symbol() {
        let source = br#"
public class Point {
    public int X, Y;
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let x = symbols
            .iter()
            .find(|s| s.name == "X" && s.kind == SymbolKind::Variable)
            .unwrap();
        let y = symbols
            .iter()
            .find(|s| s.name == "Y" && s.kind == SymbolKind::Variable)
            .unwrap();

        assert_eq!(x.range, y.range);
    }

    #[test]
    fn empty_source_returns_empty() {
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(b"").unwrap();
        assert!(symbols.is_empty());
    }

    #[test]
    fn malformed_source_recovers_partial_symbols() {
        let source = br#"
public class Stable { }

public class Broken {
    void Missing(
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "Stable"));
    }

    // === Import extraction tests ===

    #[test]
    fn extracts_using_directives() {
        let source = br#"
using System;
using System.Collections.Generic;
using MyApp.Services;
"#;
        let analyzer = CSharpAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].source, "System");
        assert_eq!(imports[1].source, "System.Collections.Generic");
        assert_eq!(imports[2].source, "MyApp.Services");
    }

    #[test]
    fn extracts_aliased_using() {
        let source = br#"
using Json = System.Text.Json;
using static System.Math;
"#;
        let analyzer = CSharpAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].source, "System.Text.Json");
        assert!(imports[0].symbols.iter().any(|s| s.name == "Json"));
    }

    #[test]
    fn extracts_static_using_source() {
        let source = br#"
using static System.Math;
"#;
        let analyzer = CSharpAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "System.Math");
    }

    #[test]
    fn extracts_usings_inside_namespace() {
        let source = br#"
namespace MyApp {
    using System.Linq;

    public class Processor { }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert!(imports.iter().any(|i| i.source == "System.Linq"));
    }

    #[test]
    fn usings_after_file_scoped_namespace_are_collected() {
        let source = br#"
namespace MyApp.Core;
using System.Text;

public class Worker { }
"#;
        let analyzer = CSharpAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert!(imports.iter().any(|i| i.source == "System.Text"));
    }

    // === Export detection tests ===

    #[test]
    fn exports_only_public_symbols() {
        let source = br#"
public class PublicClass { }
internal class InternalClass { }
class DefaultClass { }
public interface IPublic { }
private struct PrivateStruct { }
"#;
        let analyzer = CSharpAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"PublicClass"));
        assert!(names.contains(&"IPublic"));
        assert!(!names.contains(&"InternalClass"));
        assert!(!names.contains(&"DefaultClass"));
        assert!(!names.contains(&"PrivateStruct"));
    }

    // === Schema file detection tests ===

    #[test]
    fn schema_file_detection() {
        let analyzer = CSharpAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("MyApp.csproj")));
        assert!(analyzer.is_schema_file(Path::new("src/MyApp/MyApp.csproj")));
        assert!(analyzer.is_schema_file(Path::new("MySolution.sln")));
        assert!(analyzer.is_schema_file(Path::new("Directory.Build.props")));
        assert!(analyzer.is_schema_file(Path::new("Directory.Build.targets")));
        assert!(analyzer.is_schema_file(Path::new("global.json")));
        assert!(analyzer.is_schema_file(Path::new("nuget.config")));
        assert!(!analyzer.is_schema_file(Path::new("Program.cs")));
        assert!(!analyzer.is_schema_file(Path::new("README.md")));
    }

    #[test]
    fn public_members_inside_class_are_exported() {
        let source = br#"
public class Service {
    public void DoWork() { }
    private void Helper() { }
    public string Name { get; set; }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Service"));
        assert!(names.contains(&"DoWork"));
        assert!(names.contains(&"Name"));
        assert!(!names.contains(&"Helper"));
    }

    // === Stress tests and edge cases ===

    #[test]
    fn empty_source_returns_empty_all_methods() {
        let analyzer = CSharpAnalyzer::new();
        assert!(analyzer.extract_symbols(b"").unwrap().is_empty());
        assert!(analyzer.extract_imports(b"").unwrap().is_empty());
        assert!(analyzer.extract_exports(b"").unwrap().is_empty());
    }

    #[test]
    fn malformed_source_recovers() {
        let source = br#"
public class ValidClass {}

public class Broken {
    void Missing(
    public string Oops
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "ValidClass" && s.kind == SymbolKind::Class)
        );
    }

    #[test]
    fn large_namespace_with_many_classes() {
        let mut source = String::from("namespace Stress {\n");
        for i in 0..100 {
            source.push_str(&format!("    public class Class{i} {{}}\n"));
        }
        source.push_str("}\n");

        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source.as_bytes()).unwrap();
        let exports = analyzer.extract_exports(source.as_bytes()).unwrap();

        for i in 0..100 {
            let name = format!("Class{i}");
            assert!(
                symbols.iter().any(|s| s.name == name),
                "symbol Class{i} not found"
            );
            assert!(
                exports.iter().any(|e| e.name == name),
                "export Class{i} not found"
            );
        }
    }

    #[test]
    fn deeply_nested_namespaces() {
        let source = br#"
namespace A {
    namespace B {
        namespace C {
            public class Deep {}
        }
    }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Deep" && s.kind == SymbolKind::Class)
        );
    }

    #[test]
    fn realistic_aspnet_controller() {
        let source = br#"
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using MyApp.Services;

namespace MyApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        public async Task<IActionResult> GetAll()
        {
            var users = await _userService.GetAllAsync();
            return Ok(users);
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] CreateUserDto dto)
        {
            var user = await _userService.CreateAsync(dto);
            return CreatedAtAction(nameof(GetAll), user);
        }

        private void ValidateDto(CreateUserDto dto) { }
    }
}
"#;
        let analyzer = CSharpAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "UsersController" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "UsersController" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "GetAll" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Create" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "ValidateDto" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "_userService" && s.kind == SymbolKind::Variable)
        );

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 3);
        assert!(
            imports
                .iter()
                .any(|i| i.source == "Microsoft.AspNetCore.Mvc")
        );
        assert!(imports.iter().any(|i| i.source == "System.Threading.Tasks"));
        assert!(imports.iter().any(|i| i.source == "MyApp.Services"));

        let exports = analyzer.extract_exports(source).unwrap();
        let export_names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(export_names.contains(&"UsersController"));
        assert!(export_names.contains(&"GetAll"));
        assert!(export_names.contains(&"Create"));
        assert!(!export_names.contains(&"ValidateDto"));
    }

    #[test]
    fn generic_types_with_constraints() {
        let source = br#"
public class Repository<T> where T : class, IEntity
{
    public async Task<T> FindAsync<T>(int id)
    {
        return default;
    }

    public void AddRange<TItem>(IEnumerable<TItem> items) where TItem : T { }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Repository" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "FindAsync" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "AddRange" && s.kind == SymbolKind::Method)
        );
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = br#"using System;

public class Main {
    public void First() {}

    public void Second() {}
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let first = symbols.iter().find(|s| s.name == "First").unwrap();
        assert_eq!(first.range.start, 4);
        let second = symbols.iter().find(|s| s.name == "Second").unwrap();
        assert_eq!(second.range.start, 6);

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports[0].line, 1);
    }

    #[test]
    fn parse_cache_returns_consistent_results() {
        let source = br#"
public class Cached {
    public void Method() {}
}
"#;
        let analyzer = CSharpAnalyzer::new();
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
// public class NotAClass {}
/* public interface NotAnInterface {} */
/// <summary>
/// public class AlsoNotAClass {}
/// </summary>
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.is_empty());
    }

    #[test]
    fn partial_classes_and_interfaces() {
        let source = br#"
public partial class Foo {
    public void PartA() {}
}

public partial class Foo {
    public void PartB() {}
}

public partial interface IBar {
    void DoSomething();
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let foo_classes: Vec<_> = symbols
            .iter()
            .filter(|s| s.name == "Foo" && s.kind == SymbolKind::Class)
            .collect();
        assert_eq!(
            foo_classes.len(),
            2,
            "both partial class declarations should be extracted"
        );

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "PartA" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "PartB" && s.kind == SymbolKind::Method)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "IBar" && s.kind == SymbolKind::Interface)
        );
    }

    #[test]
    fn records_and_init_properties() {
        let source = br#"
public record Person(string Name, int Age);

public class Config {
    public int Count { get; init; }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Person" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Config" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Count" && s.kind == SymbolKind::Variable)
        );
    }

    #[test]
    fn nullable_reference_types() {
        let source = br#"
public class NullableExample {
    public string? Name { get; set; }
    public List<int?> Numbers { get; set; }
    public Nullable<DateTime> Timestamp { get; set; }

    public string? GetNullable() { return null; }
}
"#;
        let analyzer = CSharpAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "NullableExample" && s.kind == SymbolKind::Class)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Name" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Numbers" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Timestamp" && s.kind == SymbolKind::Variable)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "GetNullable" && s.kind == SymbolKind::Method)
        );
    }
}
