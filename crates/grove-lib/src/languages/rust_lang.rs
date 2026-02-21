use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

struct ParseCache {
    source: Vec<u8>,
    tree: tree_sitter::Tree,
}

pub struct RustAnalyzer {
    parser: std::sync::Mutex<Parser>,
    parse_cache: std::sync::Mutex<Option<ParseCache>>,
}

impl Default for RustAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RustAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("failed to set rust language");
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
                .ok_or_else(|| AnalysisError::ParseError("rust parse failed".into()))?
        };

        let mut cache = self.parse_cache.lock().unwrap();
        *cache = Some(ParseCache {
            source: source.to_vec(),
            tree: tree.clone(),
        });

        Ok(tree)
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
        let tree = self.parse(source)?;
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
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut imports = Vec::new();
        visit_descendants(root, &mut |node| {
            if node.kind() == "use_declaration" {
                let text = node.utf8_text(source).unwrap_or("").to_string();
                let line = node.start_position().row as u32 + 1;
                let path = text
                    .trim()
                    .trim_start_matches("use ")
                    .trim_end_matches(';')
                    .trim()
                    .to_string();

                imports.push(Import {
                    source: path,
                    symbols: vec![], // TODO: parse use tree for individual symbols
                    line,
                });
            }
        });

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        // In Rust, "pub" items are exports. Check for pub visibility.
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut exports = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if is_bare_pub_visibility(child, source) {
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

fn is_bare_pub_visibility(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            return child.utf8_text(source).unwrap_or("").trim() == "pub";
        }
    }
    false
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

    #[test]
    fn extracts_impl_for_generic_types() {
        let source = br#"
struct Repo<T> {
    value: T,
}

impl<T> Repo<T> {
    fn new(value: T) -> Self {
        Self { value }
    }
}
"#;

        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Struct && s.name == "Repo")
        );
        assert!(symbols.iter().any(|s| s.kind == SymbolKind::Impl));
    }

    #[test]
    fn pub_crate_items_are_not_treated_as_public_exports() {
        let source = br#"
pub(crate) fn internal_api() {}
pub fn public_api() {}
"#;

        let analyzer = RustAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert!(!exports.iter().any(|e| e.name == "internal_api"));
        assert!(exports.iter().any(|e| e.name == "public_api"));
    }

    #[test]
    fn nested_module_use_statements_are_collected_recursively() {
        let source = br#"
mod nested {
    use crate::foo::Bar;
}
use std::fmt::Debug;
"#;

        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 2);
        assert!(imports.iter().any(|i| i.source.contains("std::fmt::Debug")));
        assert!(imports.iter().any(|i| i.source.contains("crate::foo::Bar")));
    }

    #[test]
    fn schema_file_detection_matches_build_rs_and_cargo_toml() {
        let analyzer = RustAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("Cargo.toml")));
        assert!(analyzer.is_schema_file(Path::new("build.rs")));
        assert!(!analyzer.is_schema_file(Path::new("src/lib.rs")));
    }

    #[test]
    fn malformed_rust_still_yields_parse_result_and_earlier_symbols() {
        let source = br#"
fn stable() {}

impl Broken {
    fn missing(&self)
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "stable"));
    }

    #[test]
    fn top_level_and_nested_use_are_collected() {
        let source = br#"
mod nested {
    use crate::deep::Thing;
}

use std::fmt::Debug;
"#;
        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert!(imports.iter().any(|i| i.source.contains("std::fmt::Debug")));
        assert!(
            imports
                .iter()
                .any(|i| i.source.contains("crate::deep::Thing"))
        );
    }

    #[test]
    fn complex_use_tree_and_alias_are_preserved_in_import_source() {
        let source = br#"
use crate::http::{self, Method as Verb, headers::*};
"#;
        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 1);
        let raw = &imports[0].source;
        assert!(raw.contains("crate::http"));
        assert!(raw.contains("Method as Verb"));
        assert!(raw.contains("headers::*"));
    }

    #[test]
    fn restricted_pub_visibilities_are_not_treated_as_exports() {
        let source = br#"
pub(crate) fn crate_visible() {}
pub(super) struct SuperVisible;
pub(in crate::internal) fn scoped_visible() {}
pub fn public_visible() {}
"#;
        let analyzer = RustAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        assert!(!exports.iter().any(|e| e.name == "crate_visible"));
        assert!(!exports.iter().any(|e| e.name == "SuperVisible"));
        assert!(!exports.iter().any(|e| e.name == "scoped_visible"));
        assert!(exports.iter().any(|e| e.name == "public_visible"));
    }

    #[test]
    fn trait_impl_symbol_tracks_target_type_name() {
        let source = br#"
struct Repo<T>(T);

impl<T: std::fmt::Display> std::fmt::Display for Repo<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let impl_symbol = symbols.iter().find(|s| s.kind == SymbolKind::Impl).unwrap();
        assert!(impl_symbol.name.contains("Repo"));
    }

    #[test]
    fn extract_imports_reports_stable_line_numbers_for_sparse_files() {
        let source = br#"use std::fmt::Debug;

fn local() {}

use crate::core::Engine;
"#;
        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].line, 1);
        assert_eq!(imports[1].line, 5);
    }

    #[test]
    fn schema_file_detection_is_filename_based_and_case_sensitive() {
        let analyzer = RustAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("nested/project/Cargo.toml")));
        assert!(!analyzer.is_schema_file(Path::new("nested/project/cargo.toml")));
        assert!(!analyzer.is_schema_file(Path::new("nested/project/build.RS")));
    }

    // === Stress tests and edge cases ===

    #[test]
    fn empty_source_returns_empty() {
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(b"").unwrap();
        let imports = analyzer.extract_imports(b"").unwrap();
        let exports = analyzer.extract_exports(b"").unwrap();
        assert!(symbols.is_empty());
        assert!(imports.is_empty());
        assert!(exports.is_empty());
    }

    #[test]
    fn malformed_source_recovers() {
        let source = br#"
fn broken( {
    // unclosed brace and bad params
}

fn valid_after_error() -> bool {
    true
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "valid_after_error" && s.kind == SymbolKind::Function),
            "tree-sitter should recover and find the valid function after broken syntax"
        );
    }

    #[test]
    fn large_module_with_many_functions() {
        let mut source = String::new();
        for i in 0..100 {
            source.push_str(&format!("pub fn func_{i}() {{}}\n"));
        }
        let analyzer = RustAnalyzer::new();

        let symbols = analyzer.extract_symbols(source.as_bytes()).unwrap();
        let fn_symbols: Vec<_> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .collect();
        assert_eq!(fn_symbols.len(), 100);
        for i in 0..100 {
            assert!(
                fn_symbols.iter().any(|s| s.name == format!("func_{i}")),
                "missing func_{i}"
            );
        }

        let exports = analyzer.extract_exports(source.as_bytes()).unwrap();
        assert_eq!(exports.len(), 100);
    }

    #[test]
    fn deeply_nested_modules() {
        let source = br#"
mod a {
    mod b {
        mod c {
            pub fn deep() {}
        }
    }
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        // extract_symbols only walks top-level children, so `deep` is nested
        // inside mod items and won't appear as a top-level symbol. However,
        // extract_imports uses visit_descendants. Verify at least the module
        // structure is captured (no panic) and check via imports if nested
        // use statements would be found.
        assert!(
            !symbols.iter().any(|s| s.name == "deep"),
            "deeply nested fn should not appear as a top-level symbol"
        );

        // But imports *are* collected recursively, so verify that works:
        let import_source = br#"
mod a {
    mod b {
        mod c {
            use std::fmt::Debug;
            pub fn deep() {}
        }
    }
}
"#;
        let imports = analyzer.extract_imports(import_source).unwrap();
        assert!(
            imports.iter().any(|i| i.source.contains("std::fmt::Debug")),
            "nested imports should be collected recursively"
        );
    }

    #[test]
    fn realistic_axum_handler() {
        let source = br#"
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CreateUserRequest {
    name: String,
    email: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    id: u64,
    name: String,
}

pub async fn create_user(
    State(pool): State<DbPool>,
    Json(payload): Json<CreateUserRequest>,
) -> impl IntoResponse {
    Json(UserResponse { id: 1, name: payload.name })
}

impl UserResponse {
    fn from_model(user: User) -> Self {
        Self {
            id: user.id,
            name: user.name,
        }
    }
}
"#;
        let analyzer = RustAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "CreateUserRequest" && s.kind == SymbolKind::Struct));
        assert!(symbols.iter().any(|s| s.name == "UserResponse" && s.kind == SymbolKind::Struct));
        assert!(symbols.iter().any(|s| s.name == "create_user" && s.kind == SymbolKind::Function));
        assert!(symbols.iter().any(|s| s.name == "UserResponse" && s.kind == SymbolKind::Impl));

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 2);
        assert!(imports.iter().any(|i| i.source.contains("axum")));
        assert!(imports.iter().any(|i| i.source.contains("serde")));

        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.iter().any(|e| e.name == "CreateUserRequest" && e.kind == SymbolKind::Struct));
        assert!(exports.iter().any(|e| e.name == "UserResponse" && e.kind == SymbolKind::Struct));
        assert!(exports.iter().any(|e| e.name == "create_user" && e.kind == SymbolKind::Function));
    }

    #[test]
    fn generic_types_with_lifetime_annotations() {
        let source = br#"
pub struct Cache<'a, K: Hash + Eq, V> {
    store: &'a HashMap<K, V>,
}

pub fn get<'a, T: Display>(cache: &'a Cache<'a, String, T>, key: &str) -> Option<&'a T> {
    None
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols.iter().any(|s| s.name == "Cache" && s.kind == SymbolKind::Struct),
            "generic struct with lifetimes should be extracted"
        );
        assert!(
            symbols.iter().any(|s| s.name == "get" && s.kind == SymbolKind::Function),
            "generic function with lifetimes should be extracted"
        );
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = b"fn first() {}\n\n\nfn second() {}\n";
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);

        let first = symbols.iter().find(|s| s.name == "first").unwrap();
        assert_eq!(first.range.start, 1, "first fn should be on line 1 (1-based)");

        let second = symbols.iter().find(|s| s.name == "second").unwrap();
        assert_eq!(second.range.start, 4, "second fn should be on line 4 (1-based)");
    }

    #[test]
    fn parse_cache_returns_consistent_results() {
        let source = br#"
fn cached_fn() -> u32 { 42 }
pub struct CachedStruct;
"#;
        let analyzer = RustAnalyzer::new();
        let first = analyzer.extract_symbols(source).unwrap();
        let second = analyzer.extract_symbols(source).unwrap();

        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.range.start, b.range.start);
            assert_eq!(a.range.end, b.range.end);
        }
    }

    #[test]
    fn comments_do_not_produce_symbols() {
        let source = br#"
// fn not_a_function() {}
/* struct NotAStruct; */
/// doc comment referencing fn documented_thing()
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let imports = analyzer.extract_imports(source).unwrap();
        let exports = analyzer.extract_exports(source).unwrap();
        assert!(symbols.is_empty(), "comments should not produce symbols");
        assert!(imports.is_empty(), "comments should not produce imports");
        assert!(exports.is_empty(), "comments should not produce exports");
    }

    #[test]
    fn trait_impl_methods_extracted() {
        let source = br#"
trait Foo {
    fn bar(&self) -> u32;
}

struct MyStruct;

impl Foo for MyStruct {
    fn bar(&self) -> u32 {
        42
    }
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols.iter().any(|s| s.name == "Foo" && s.kind == SymbolKind::Trait),
            "trait definition should be extracted"
        );
        assert!(
            symbols.iter().any(|s| s.name == "MyStruct" && s.kind == SymbolKind::Struct),
            "struct definition should be extracted"
        );
        assert!(
            symbols.iter().any(|s| s.kind == SymbolKind::Impl),
            "impl block should be extracted"
        );
    }

    #[test]
    fn macro_invocations_dont_crash() {
        let source = br#"
macro_rules! my_macro {
    ($x:expr) => { println!("{}", $x); };
}

fn uses_macros() {
    let v = vec![1, 2, 3];
    println!("hello");
    my_macro!(42);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Derived {
    field: String,
}
"#;
        let analyzer = RustAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let imports = analyzer.extract_imports(source).unwrap();
        let exports = analyzer.extract_exports(source).unwrap();

        // Should not panic and should find the valid items
        assert!(symbols.iter().any(|s| s.name == "uses_macros" && s.kind == SymbolKind::Function));
        assert!(symbols.iter().any(|s| s.name == "Derived" && s.kind == SymbolKind::Struct));
        // macro_rules definitions are not tracked as symbols
        assert!(!symbols.iter().any(|s| s.name == "my_macro"));
        // No pub items, so exports should be empty
        assert!(exports.is_empty());
        // No use statements, so imports should be empty
        assert!(imports.is_empty());
    }

    #[test]
    fn pub_use_re_exports() {
        let source = br#"
pub use crate::foo::Bar;
pub use super::*;
use std::collections::HashMap;
"#;
        let analyzer = RustAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 3);
        assert!(imports.iter().any(|i| i.source.contains("crate::foo::Bar")));
        assert!(imports.iter().any(|i| i.source.contains("super::*")));
        assert!(imports.iter().any(|i| i.source.contains("std::collections::HashMap")));
    }
}
