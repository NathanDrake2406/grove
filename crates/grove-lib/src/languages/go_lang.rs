use super::{AnalysisError, LanguageAnalyzer};
use crate::types::*;
use std::path::Path;
use tree_sitter::Parser;

struct ParseCache {
    source: Vec<u8>,
    tree: tree_sitter::Tree,
}

pub struct GoAnalyzer {
    parser: std::sync::Mutex<Parser>,
    parse_cache: std::sync::Mutex<Option<ParseCache>>,
}

impl Default for GoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl GoAnalyzer {
    pub fn new() -> Self {
        let mut parser = Parser::new();
        // Grammar ABI compatibility is a build/link invariant; failure means the build is broken.
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("failed to set go language");
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
                .ok_or_else(|| AnalysisError::ParseError("go parse failed".into()))?
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

fn is_exported(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_uppercase())
}

impl LanguageAnalyzer for GoAnalyzer {
    fn language_id(&self) -> &str {
        "go"
    }

    fn file_extensions(&self) -> &[&str] {
        &["go"]
    }

    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        let tree = self.parse(source)?;
        let root = tree.root_node();
        let mut symbols = Vec::new();
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            match child.kind() {
                "function_declaration" => {
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
                "type_declaration" => {
                    extract_type_symbols(child, source, &mut symbols);
                }
                "const_declaration" => {
                    extract_spec_symbols(
                        child,
                        source,
                        "const_spec",
                        SymbolKind::Constant,
                        &mut symbols,
                    );
                }
                "var_declaration" => {
                    extract_spec_symbols(
                        child,
                        source,
                        "var_spec",
                        SymbolKind::Variable,
                        &mut symbols,
                    );
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
        let mut cursor = root.walk();

        for child in root.children(&mut cursor) {
            if child.kind() == "import_declaration" {
                collect_import_specs(child, source, &mut imports);
            }
        }

        Ok(imports)
    }

    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        let symbols = self.extract_symbols(source)?;
        Ok(symbols
            .into_iter()
            .filter(|s| is_exported(&s.name))
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
            "go.mod" | "go.sum" | "go.work" | "go.work.sum"
        )
    }
}

fn extract_type_symbols(
    type_decl: tree_sitter::Node<'_>,
    source: &[u8],
    symbols: &mut Vec<Symbol>,
) {
    let mut cursor = type_decl.walk();
    for child in type_decl.children(&mut cursor) {
        match child.kind() {
            "type_spec" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_string();
                    let kind = child
                        .child_by_field_name("type")
                        .map(|t| match t.kind() {
                            "struct_type" => SymbolKind::Struct,
                            "interface_type" => SymbolKind::Interface,
                            _ => SymbolKind::TypeAlias,
                        })
                        .unwrap_or(SymbolKind::TypeAlias);

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
            "type_alias" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    symbols.push(Symbol {
                        name: name_node.utf8_text(source).unwrap_or("").to_string(),
                        kind: SymbolKind::TypeAlias,
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
}

/// Extract symbols from const_spec or var_spec children of a declaration node.
/// Handles both single declarations and grouped blocks (with spec list wrappers).
fn extract_spec_symbols(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    spec_kind: &str,
    symbol_kind: SymbolKind,
    symbols: &mut Vec<Symbol>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == spec_kind {
            let mut name_cursor = child.walk();
            for name_child in child.children_by_field_name("name", &mut name_cursor) {
                if name_child.kind() == "identifier" || name_child.kind() == "type_identifier" {
                    symbols.push(Symbol {
                        name: name_child.utf8_text(source).unwrap_or("").to_string(),
                        kind: symbol_kind,
                        range: LineRange {
                            start: child.start_position().row as u32 + 1,
                            end: child.end_position().row as u32 + 1,
                        },
                        signature: None,
                    });
                }
            }
        } else if child.kind() == "var_spec_list" {
            extract_spec_symbols(child, source, spec_kind, symbol_kind, symbols);
        }
    }
}

/// Collect import specs from an import_declaration or import_spec_list node.
fn collect_import_specs(node: tree_sitter::Node<'_>, source: &[u8], imports: &mut Vec<Import>) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "import_spec" => {
                if let Some(path_node) = child.child_by_field_name("path") {
                    let raw_path = path_node.utf8_text(source).unwrap_or("");
                    let path = raw_path.trim_matches('"').trim_matches('`').to_string();

                    let alias = child
                        .child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source).ok())
                        .map(|s| s.to_string());

                    let symbols = alias
                        .as_ref()
                        .map(|a| {
                            vec![ImportedSymbol {
                                name: a.clone(),
                                alias: None,
                            }]
                        })
                        .unwrap_or_default();

                    imports.push(Import {
                        source: path,
                        symbols,
                        line: child.start_position().row as u32 + 1,
                    });
                }
            }
            "import_spec_list" => {
                collect_import_specs(child, source, imports);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_go_function_symbols() {
        let source = br#"package main

func processPayment(amount int) bool {
    return true
}

func (s *Server) HandleRequest(w http.ResponseWriter, r *http.Request) {
    // method
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "processPayment");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert!(
            symbols[0]
                .signature
                .as_ref()
                .unwrap()
                .contains("func processPayment")
        );
        assert_eq!(symbols[1].name, "HandleRequest");
        assert_eq!(symbols[1].kind, SymbolKind::Method);
    }

    #[test]
    fn extracts_go_struct_and_interface() {
        let source = br#"package main

type User struct {
    Name string
    Age  int
}

type Handler interface {
    Handle(req Request) Response
}

type Duration int64
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "User");
        assert_eq!(symbols[0].kind, SymbolKind::Struct);
        assert_eq!(symbols[1].name, "Handler");
        assert_eq!(symbols[1].kind, SymbolKind::Interface);
        assert_eq!(symbols[2].name, "Duration");
        assert_eq!(symbols[2].kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn extracts_go_imports() {
        let source = br#"package main

import "fmt"

import (
    "os"
    "net/http"
)
"#;
        let analyzer = GoAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].source, "fmt");
        assert_eq!(imports[1].source, "os");
        assert_eq!(imports[2].source, "net/http");
    }

    #[test]
    fn extracts_go_exports_by_capitalization() {
        let source = br#"package main

func ExportedFunc() {}
func privateFunc() {}

type ExportedType struct {}
type privateType struct {}
"#;
        let analyzer = GoAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();

        let names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"ExportedFunc"));
        assert!(names.contains(&"ExportedType"));
        assert!(!names.contains(&"privateFunc"));
        assert!(!names.contains(&"privateType"));
        assert_eq!(exports.len(), 2);
    }

    #[test]
    fn extracts_go_constants_and_vars() {
        let source = br#"package main

const MaxRetries = 3

const (
    StatusOK    = 200
    StatusError = 500
)

var globalClient *http.Client

var (
    debugMode bool
    Version   string
)
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let consts: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Constant)
            .collect();
        assert_eq!(consts.len(), 3);
        assert_eq!(consts[0].name, "MaxRetries");
        assert_eq!(consts[1].name, "StatusOK");
        assert_eq!(consts[2].name, "StatusError");

        let vars: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Variable)
            .collect();
        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].name, "globalClient");
        assert_eq!(vars[1].name, "debugMode");
        assert_eq!(vars[2].name, "Version");
    }

    #[test]
    fn blank_and_dot_imports_are_handled() {
        let source = br#"package main

import (
    _ "database/sql"
    . "math"
    custom "encoding/json"
)
"#;
        let analyzer = GoAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();

        assert_eq!(imports.len(), 3);

        assert_eq!(imports[0].source, "database/sql");
        assert_eq!(imports[0].symbols[0].name, "_");

        assert_eq!(imports[1].source, "math");
        assert_eq!(imports[1].symbols[0].name, ".");

        assert_eq!(imports[2].source, "encoding/json");
        assert_eq!(imports[2].symbols[0].name, "custom");
    }

    #[test]
    fn malformed_go_source_recovers() {
        let source = br#"package main

func stableFunc() {}

func brokenFunc( {
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "stableFunc"));
    }

    #[test]
    fn schema_file_detection() {
        let analyzer = GoAnalyzer::new();
        assert!(analyzer.is_schema_file(Path::new("go.mod")));
        assert!(analyzer.is_schema_file(Path::new("go.sum")));
        assert!(analyzer.is_schema_file(Path::new("go.work")));
        assert!(analyzer.is_schema_file(Path::new("go.work.sum")));
        assert!(analyzer.is_schema_file(Path::new("myproject/go.mod")));
        assert!(!analyzer.is_schema_file(Path::new("main.go")));
        assert!(!analyzer.is_schema_file(Path::new("go.mod.bak")));
    }

    #[test]
    fn unexported_symbols_excluded_from_exports() {
        let source = br#"package main

func helper() {}
const maxSize = 100
var cache map[string]string
type internal struct {}
"#;
        let analyzer = GoAnalyzer::new();
        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.is_empty());
    }

    // === Stress tests ===

    #[test]
    fn generics_type_parameters_are_handled() {
        let source = br#"package collections

type Set[T comparable] struct {
    items map[T]struct{}
}

type Pair[A, B any] struct {
    First  A
    Second B
}

func Map[T, U any](slice []T, f func(T) U) []U {
    result := make([]U, len(slice))
    for i, v := range slice {
        result[i] = f(v)
    }
    return result
}

func (s *Set[T]) Add(item T) {
    s.items[item] = struct{}{}
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Set" && s.kind == SymbolKind::Struct)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Pair" && s.kind == SymbolKind::Struct)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Map" && s.kind == SymbolKind::Function)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Add" && s.kind == SymbolKind::Method)
        );
    }

    #[test]
    fn iota_const_block() {
        let source = br#"package main

const (
    Red = iota
    Green
    Blue
)
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Red", "Green", "Blue"]);
        assert!(symbols.iter().all(|s| s.kind == SymbolKind::Constant));
    }

    #[test]
    fn multi_name_var_declaration() {
        let source = br#"package main

var x, y, z int
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["x", "y", "z"]);
        assert!(symbols.iter().all(|s| s.kind == SymbolKind::Variable));
    }

    #[test]
    fn multi_name_const_declaration() {
        let source = br#"package main

const a, b = 1, 2
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn type_alias_with_equals_sign() {
        let source = br#"package main

type MyInt = int
type MyMap = map[string]interface{}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert!(symbols.iter().all(|s| s.kind == SymbolKind::TypeAlias));
        assert_eq!(symbols[0].name, "MyInt");
        assert_eq!(symbols[1].name, "MyMap");
    }

    #[test]
    fn grouped_type_declaration() {
        let source = br#"package main

type (
    Request struct {
        URL    string
        Method string
    }
    Response struct {
        Status int
        Body   []byte
    }
    Handler interface {
        ServeHTTP(Response, *Request)
    }
    Middleware func(Handler) Handler
)
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 4);
        assert_eq!(symbols[0].name, "Request");
        assert_eq!(symbols[0].kind, SymbolKind::Struct);
        assert_eq!(symbols[1].name, "Response");
        assert_eq!(symbols[1].kind, SymbolKind::Struct);
        assert_eq!(symbols[2].name, "Handler");
        assert_eq!(symbols[2].kind, SymbolKind::Interface);
        assert_eq!(symbols[3].name, "Middleware");
        assert_eq!(symbols[3].kind, SymbolKind::TypeAlias);
    }

    #[test]
    fn init_function_is_extracted() {
        let source = br#"package main

func init() {
    setupDB()
}

func main() {
    run()
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "init"));
        assert!(symbols.iter().any(|s| s.name == "main"));

        // init is not exported (lowercase)
        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.is_empty());
    }

    #[test]
    fn empty_source_returns_empty() {
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(b"").unwrap();
        assert!(symbols.is_empty());
        let imports = analyzer.extract_imports(b"").unwrap();
        assert!(imports.is_empty());
        let exports = analyzer.extract_exports(b"").unwrap();
        assert!(exports.is_empty());
    }

    #[test]
    fn package_only_returns_empty() {
        let source = b"package main\n";
        let analyzer = GoAnalyzer::new();
        assert!(analyzer.extract_symbols(source).unwrap().is_empty());
        assert!(analyzer.extract_imports(source).unwrap().is_empty());
        assert!(analyzer.extract_exports(source).unwrap().is_empty());
    }

    #[test]
    fn embedded_interface_still_classified_as_interface() {
        let source = br#"package io

type ReadWriter interface {
    Reader
    Writer
}

type ReadCloser interface {
    Read(p []byte) (n int, err error)
    Close() error
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert!(symbols.iter().all(|s| s.kind == SymbolKind::Interface));
    }

    #[test]
    fn method_with_value_and_pointer_receiver() {
        let source = br#"package main

type Buffer struct{ data []byte }

func (b Buffer) Len() int { return len(b.data) }
func (b *Buffer) Reset() { b.data = b.data[:0] }
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let methods: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Method)
            .collect();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0].name, "Len");
        assert_eq!(methods[1].name, "Reset");
    }

    #[test]
    fn multiple_return_values_in_signature() {
        let source = br#"package main

func Divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("division by zero")
    }
    return a / b, nil
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 1);
        let sig = symbols[0].signature.as_ref().unwrap();
        assert!(sig.contains("Divide"));
        assert!(sig.contains("float64"));
    }

    #[test]
    fn raw_string_literal_import() {
        let source = "package main\n\nimport `fmt`\n".as_bytes();
        let analyzer = GoAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "fmt");
    }

    #[test]
    fn comments_do_not_produce_symbols() {
        let source = br#"package main

// func NotAFunction() {}
/* type NotAType struct {} */

func RealFunc() {}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "RealFunc");
    }

    #[test]
    fn realistic_http_handler_file() {
        let source = br#"package handlers

import (
    "encoding/json"
    "log"
    "net/http"
    "strconv"

    "github.com/gorilla/mux"
    "myapp/internal/models"
    "myapp/internal/services"
)

const (
    defaultPageSize = 20
    maxPageSize     = 100
)

var (
    ErrNotFound    = errors.New("not found")
    ErrBadRequest  = errors.New("bad request")
)

type UserHandler struct {
    service *services.UserService
    logger  *log.Logger
}

type ErrorResponse struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
}

func NewUserHandler(svc *services.UserService, logger *log.Logger) *UserHandler {
    return &UserHandler{service: svc, logger: logger}
}

func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    id, err := strconv.Atoi(vars["id"])
    if err != nil {
        writeError(w, http.StatusBadRequest, "invalid id")
        return
    }
    user, err := h.service.FindByID(r.Context(), id)
    if err != nil {
        writeError(w, http.StatusNotFound, err.Error())
        return
    }
    json.NewEncoder(w).Encode(user)
}

func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
    users, err := h.service.List(r.Context())
    if err != nil {
        writeError(w, http.StatusInternalServerError, err.Error())
        return
    }
    json.NewEncoder(w).Encode(users)
}

func writeError(w http.ResponseWriter, code int, msg string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    json.NewEncoder(w).Encode(ErrorResponse{Code: code, Message: msg})
}
"#;
        let analyzer = GoAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        let names: Vec<&str> = symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"UserHandler"));
        assert!(names.contains(&"ErrorResponse"));
        assert!(names.contains(&"NewUserHandler"));
        assert!(names.contains(&"GetUser"));
        assert!(names.contains(&"ListUsers"));
        assert!(names.contains(&"writeError"));
        assert!(names.contains(&"defaultPageSize"));
        assert!(names.contains(&"maxPageSize"));
        assert!(names.contains(&"ErrNotFound"));
        assert!(names.contains(&"ErrBadRequest"));
        assert_eq!(symbols.len(), 10);

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 7);
        assert!(imports.iter().any(|i| i.source == "net/http"));
        assert!(imports.iter().any(|i| i.source == "github.com/gorilla/mux"));
        assert!(imports.iter().any(|i| i.source == "myapp/internal/models"));

        let exports = analyzer.extract_exports(source).unwrap();
        let export_names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(export_names.contains(&"UserHandler"));
        assert!(export_names.contains(&"ErrorResponse"));
        assert!(export_names.contains(&"NewUserHandler"));
        assert!(export_names.contains(&"GetUser"));
        assert!(export_names.contains(&"ListUsers"));
        assert!(export_names.contains(&"ErrNotFound"));
        assert!(export_names.contains(&"ErrBadRequest"));
        // writeError, defaultPageSize, maxPageSize are unexported
        assert!(!export_names.contains(&"writeError"));
        assert!(!export_names.contains(&"defaultPageSize"));
        assert!(!export_names.contains(&"maxPageSize"));
    }

    #[test]
    fn unicode_identifier_export_detection() {
        // Go supports Unicode identifiers; uppercase Unicode = exported
        let source = "package main\n\nfunc Ñoño() {}\nfunc ñoño() {}\n".as_bytes();
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);

        let exports = analyzer.extract_exports(source).unwrap();
        // Ñ is uppercase Unicode
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].name, "Ñoño");
    }

    #[test]
    fn syntax_error_mid_file_still_extracts_surrounding() {
        let source = br#"package main

func Before() {}

type Broken struct {
    field1 string
    // oops, missing closing brace

func After() {}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        // tree-sitter should recover and extract at least Before
        assert!(symbols.iter().any(|s| s.name == "Before"));
    }

    #[test]
    fn empty_interface_and_empty_struct() {
        let source = br#"package main

type Empty struct{}
type Any interface{}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].kind, SymbolKind::Struct);
        assert_eq!(symbols[1].kind, SymbolKind::Interface);
    }

    #[test]
    fn variadic_function_signature() {
        let source = br#"package main

func Printf(format string, args ...interface{}) {
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols.len(), 1);
        let sig = symbols[0].signature.as_ref().unwrap();
        assert!(sig.contains("Printf"));
        assert!(sig.contains("..."));
    }

    #[test]
    fn line_numbers_are_correct() {
        let source = br#"package main

import "fmt"

func First() {}

func Second() {}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert_eq!(symbols[0].name, "First");
        assert_eq!(symbols[0].range.start, 5);
        assert_eq!(symbols[1].name, "Second");
        assert_eq!(symbols[1].range.start, 7);

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports[0].line, 3);
    }

    #[test]
    fn registry_matches_go_files() {
        let registry = super::super::LanguageRegistry::with_defaults();
        let analyzer = registry.analyzer_for_file(Path::new("main.go"));
        assert!(analyzer.is_some());
        assert_eq!(analyzer.unwrap().language_id(), "go");

        // .go is Go, not something else
        assert!(registry.analyzer_for_file(Path::new("server.go")).is_some());
        // Not Go files
        assert_ne!(
            registry
                .analyzer_for_file(Path::new("lib.rs"))
                .unwrap()
                .language_id(),
            "go"
        );
    }

    #[test]
    fn parse_cache_returns_consistent_results() {
        let source = br#"package main
func Cached() {}
"#;
        let analyzer = GoAnalyzer::new();
        let first = analyzer.extract_symbols(source).unwrap();
        let second = analyzer.extract_symbols(source).unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0].name, second[0].name);
    }

    // === Stress tests and edge cases ===

    #[test]
    fn stress_empty_source_returns_empty() {
        let analyzer = GoAnalyzer::new();
        assert!(analyzer.extract_symbols(b"").unwrap().is_empty());
        assert!(analyzer.extract_imports(b"").unwrap().is_empty());
        assert!(analyzer.extract_exports(b"").unwrap().is_empty());
    }

    #[test]
    fn stress_malformed_source_recovers() {
        let source = br#"package main

func validFunc() {}

func brokenFunc( {
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols.iter().any(|s| s.name == "validFunc"),
            "tree-sitter should recover and find validFunc despite broken syntax"
        );
    }

    #[test]
    fn stress_large_package_with_many_functions() {
        let mut source = String::from("package main\n");
        for i in 0..100 {
            source.push_str(&format!("func Func{}() {{}}\n", i));
        }
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source.as_bytes()).unwrap();
        let funcs: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .collect();
        assert_eq!(funcs.len(), 100);
        for i in 0..100 {
            assert!(
                funcs.iter().any(|s| s.name == format!("Func{}", i)),
                "missing Func{}",
                i,
            );
        }
    }

    #[test]
    fn stress_deeply_nested_structs_and_interfaces() {
        let source = br#"package main

type Outer struct {
    Inner InnerStruct
}

type InnerStruct struct {
    Value string
}

type Composite interface {
    Embedded
}

type Embedded interface {
    DoWork()
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Outer" && s.kind == SymbolKind::Struct)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "InnerStruct" && s.kind == SymbolKind::Struct)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Composite" && s.kind == SymbolKind::Interface)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Embedded" && s.kind == SymbolKind::Interface)
        );
        assert_eq!(symbols.len(), 4);
    }

    #[test]
    fn stress_realistic_http_handler() {
        let source = br#"package api

import (
    "encoding/json"
    "fmt"
    "net/http"
)

type ApiResponse struct {
    Status  int    `json:"status"`
    Message string `json:"message"`
}

func HandleHealth(w http.ResponseWriter, r *http.Request) {
    resp := ApiResponse{Status: 200, Message: "ok"}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

func (a *ApiResponse) Format() string {
    return fmt.Sprintf("%d: %s", a.Status, a.Message)
}
"#;
        let analyzer = GoAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "ApiResponse" && s.kind == SymbolKind::Struct)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "HandleHealth" && s.kind == SymbolKind::Function)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Format" && s.kind == SymbolKind::Method)
        );

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 3);
        assert!(imports.iter().any(|i| i.source == "net/http"));
        assert!(imports.iter().any(|i| i.source == "encoding/json"));
        assert!(imports.iter().any(|i| i.source == "fmt"));

        let exports = analyzer.extract_exports(source).unwrap();
        let export_names: Vec<&str> = exports.iter().map(|e| e.name.as_str()).collect();
        assert!(export_names.contains(&"ApiResponse"));
        assert!(export_names.contains(&"HandleHealth"));
        assert!(export_names.contains(&"Format"));
    }

    #[test]
    fn stress_generic_types_go118() {
        let source = br#"package collections

type Set[T comparable] struct {
    items map[T]struct{}
}

func Map[T, U any](slice []T, f func(T) U) []U {
    result := make([]U, len(slice))
    for i, v := range slice {
        result[i] = f(v)
    }
    return result
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Set" && s.kind == SymbolKind::Struct)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Map" && s.kind == SymbolKind::Function)
        );
    }

    #[test]
    fn stress_line_numbers_are_correct() {
        let source = b"package main\n\nfunc Alpha() {}\n\nfunc Beta() {}\n";
        // Line 1: package main
        // Line 2: (empty)
        // Line 3: func Alpha() {}
        // Line 4: (empty)
        // Line 5: func Beta() {}
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols[0].name, "Alpha");
        assert_eq!(
            symbols[0].range.start, 3,
            "Alpha should be on line 3 (1-based)"
        );
        assert_eq!(symbols[1].name, "Beta");
        assert_eq!(
            symbols[1].range.start, 5,
            "Beta should be on line 5 (1-based)"
        );
    }

    #[test]
    fn stress_parse_cache_returns_consistent_results() {
        let source = br#"package main

func Cached() {}
type CachedType struct {}
"#;
        let analyzer = GoAnalyzer::new();
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
    fn stress_comments_do_not_produce_symbols() {
        let source = br#"package main

// func FakeFunc() {}
// type FakeType struct {}

/*
func BlockCommentFunc() {}
type BlockCommentType struct {}
*/
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols.is_empty(),
            "comments should not produce symbols, found: {:?}",
            symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn stress_interface_method_sets() {
        let source = br#"package io

type Reader interface {
    Read(p []byte) (n int, err error)
}

type ReadWriter interface {
    Reader
    Write(p []byte) (n int, err error)
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert!(
            symbols
                .iter()
                .any(|s| s.name == "Reader" && s.kind == SymbolKind::Interface)
        );
        assert!(
            symbols
                .iter()
                .any(|s| s.name == "ReadWriter" && s.kind == SymbolKind::Interface)
        );

        let exports = analyzer.extract_exports(source).unwrap();
        assert_eq!(exports.len(), 2);
        assert!(exports.iter().any(|e| e.name == "Reader"));
        assert!(exports.iter().any(|e| e.name == "ReadWriter"));
    }

    #[test]
    fn stress_init_function_and_blank_imports() {
        let source = br#"package main

import _ "embed"

func init() {
    setup()
}
"#;
        let analyzer = GoAnalyzer::new();

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(
            symbols.iter().any(|s| s.name == "init"),
            "init function should be extracted"
        );

        let imports = analyzer.extract_imports(source).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].source, "embed");
        assert_eq!(imports[0].symbols[0].name, "_");

        // init is not exported (lowercase)
        let exports = analyzer.extract_exports(source).unwrap();
        assert!(exports.is_empty(), "init should not be exported");
    }

    #[test]
    fn stress_multiple_return_values_and_named_returns() {
        let source = br#"package main

func divide(a, b int) (result int, err error) {
    if b == 0 {
        return 0, fmt.Errorf("division by zero")
    }
    return a / b, nil
}
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        assert_eq!(symbols.len(), 1);
        assert_eq!(symbols[0].name, "divide");
        assert_eq!(symbols[0].kind, SymbolKind::Function);

        let sig = symbols[0].signature.as_ref().unwrap();
        assert!(
            sig.contains("divide"),
            "signature should contain function name"
        );
        assert!(
            sig.contains("result int"),
            "signature should contain named return 'result int'"
        );
        assert!(
            sig.contains("err error"),
            "signature should contain named return 'err error'"
        );
    }

    #[test]
    fn cgo_preamble_does_not_crash() {
        let source = br#"package main

/*
#include <stdio.h>
#include <stdlib.h>
*/
import "C"

import "fmt"

func main() {
    fmt.Println(C.GoString(C.getenv(C.CString("HOME"))))
}
"#;
        let analyzer = GoAnalyzer::new();
        let imports = analyzer.extract_imports(source).unwrap();
        // "C" is the cgo pseudo-package
        assert!(imports.iter().any(|i| i.source == "C"));
        assert!(imports.iter().any(|i| i.source == "fmt"));

        let symbols = analyzer.extract_symbols(source).unwrap();
        assert!(symbols.iter().any(|s| s.name == "main"));
    }

    #[test]
    fn language_id_and_file_extensions() {
        let analyzer = GoAnalyzer::new();
        assert_eq!(analyzer.language_id(), "go");
        assert_eq!(analyzer.file_extensions(), &["go"]);
    }

    #[test]
    fn range_start_and_end_for_all_symbol_kinds() {
        let source = br#"package main

func topFunc() {
}

func (s *Server) method() {
}

type MyStruct struct {
    X int
}

type MyInterface interface {
    Do()
}

type Alias int

const MaxSize = 100

var counter int
"#;
        let analyzer = GoAnalyzer::new();
        let symbols = analyzer.extract_symbols(source).unwrap();

        let top_func = symbols.iter().find(|s| s.name == "topFunc").unwrap();
        assert_eq!(top_func.range.start, 3);
        assert_eq!(top_func.range.end, 4);

        let method = symbols.iter().find(|s| s.name == "method").unwrap();
        assert_eq!(method.range.start, 6);
        assert_eq!(method.range.end, 7);

        let my_struct = symbols.iter().find(|s| s.name == "MyStruct").unwrap();
        assert_eq!(my_struct.range.start, 9);
        assert_eq!(my_struct.range.end, 11);

        let my_iface = symbols.iter().find(|s| s.name == "MyInterface").unwrap();
        assert_eq!(my_iface.range.start, 13);
        assert_eq!(my_iface.range.end, 15);

        let alias = symbols.iter().find(|s| s.name == "Alias").unwrap();
        assert_eq!(alias.range.start, 17);
        assert_eq!(alias.range.end, 17);

        let max_size = symbols.iter().find(|s| s.name == "MaxSize").unwrap();
        assert_eq!(max_size.range.start, 19);
        assert_eq!(max_size.range.end, 19);

        let counter = symbols.iter().find(|s| s.name == "counter").unwrap();
        assert_eq!(counter.range.start, 21);
        assert_eq!(counter.range.end, 21);
    }
}
