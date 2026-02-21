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

impl LanguageAnalyzer for JavaAnalyzer {
    fn language_id(&self) -> &str {
        "java"
    }

    fn file_extensions(&self) -> &[&str] {
        &["java"]
    }

    fn extract_symbols(&self, _source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
        Ok(vec![]) // stub — tests will fail
    }

    fn extract_imports(&self, _source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
        Ok(vec![]) // stub — tests will fail
    }

    fn extract_exports(&self, _source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
        Ok(vec![]) // stub — tests will fail
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
}
