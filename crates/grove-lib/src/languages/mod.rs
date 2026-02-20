pub mod rust_lang;
pub mod typescript;

use crate::types::*;
use std::path::Path;

/// Trait for language-specific symbol and import extraction.
/// Each language implements this to provide tree-sitter-based analysis.
pub trait LanguageAnalyzer: Send + Sync {
    fn language_id(&self) -> &str;
    fn file_extensions(&self) -> &[&str];
    fn extract_symbols(&self, source: &[u8]) -> Result<Vec<Symbol>, AnalysisError>;
    fn extract_imports(&self, source: &[u8]) -> Result<Vec<Import>, AnalysisError>;
    fn extract_exports(&self, source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError>;
    fn is_schema_file(&self, path: &Path) -> bool;
}

#[derive(Debug, thiserror::Error)]
pub enum AnalysisError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("unsupported language: {0}")]
    UnsupportedLanguage(String),
}

/// Registry of language analyzers. Matches file extensions to analyzers.
pub struct LanguageRegistry {
    analyzers: Vec<Box<dyn LanguageAnalyzer>>,
}

impl Default for LanguageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LanguageRegistry {
    pub fn new() -> Self {
        Self { analyzers: vec![] }
    }

    /// Create a registry with the built-in analyzers (TypeScript, Rust).
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(typescript::TypeScriptAnalyzer::new()));
        registry.register(Box::new(rust_lang::RustAnalyzer::new()));
        registry
    }

    pub fn register(&mut self, analyzer: Box<dyn LanguageAnalyzer>) {
        self.analyzers.push(analyzer);
    }

    pub fn analyzer_for_file(&self, path: &Path) -> Option<&dyn LanguageAnalyzer> {
        let ext = path.extension()?.to_str()?;
        self.analyzers
            .iter()
            .find(|a| a.file_extensions().contains(&ext))
            .map(|a| a.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockAnalyzer {
        id: &'static str,
        exts: Vec<&'static str>,
        calls: AtomicUsize,
    }

    impl MockAnalyzer {
        fn new(id: &'static str, exts: Vec<&'static str>) -> Self {
            Self {
                id,
                exts,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl LanguageAnalyzer for MockAnalyzer {
        fn language_id(&self) -> &str {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.id
        }

        fn file_extensions(&self) -> &[&str] {
            &self.exts
        }

        fn extract_symbols(&self, _source: &[u8]) -> Result<Vec<Symbol>, AnalysisError> {
            Ok(vec![])
        }

        fn extract_imports(&self, _source: &[u8]) -> Result<Vec<Import>, AnalysisError> {
            Ok(vec![])
        }

        fn extract_exports(&self, _source: &[u8]) -> Result<Vec<ExportedSymbol>, AnalysisError> {
            Ok(vec![])
        }

        fn is_schema_file(&self, _path: &Path) -> bool {
            false
        }
    }

    #[test]
    fn language_registry_returns_none_for_missing_extension() {
        let mut registry = LanguageRegistry::new();
        registry.register(Box::new(MockAnalyzer::new("rust", vec!["rs"])));

        assert!(registry.analyzer_for_file(Path::new("src/lib")).is_none());
    }

    #[test]
    fn language_registry_matches_exact_extension_case() {
        let mut registry = LanguageRegistry::new();
        registry.register(Box::new(MockAnalyzer::new("rust", vec!["rs"])));

        assert!(registry.analyzer_for_file(Path::new("src/lib.RS")).is_none());
        assert_eq!(
            registry
                .analyzer_for_file(Path::new("src/lib.rs"))
                .unwrap()
                .language_id(),
            "rust"
        );
    }

    #[test]
    fn language_registry_uses_first_registered_match_for_same_extension() {
        let mut registry = LanguageRegistry::new();
        registry.register(Box::new(MockAnalyzer::new("first", vec!["ts"])));
        registry.register(Box::new(MockAnalyzer::new("second", vec!["ts"])));

        let analyzer = registry.analyzer_for_file(Path::new("mod.ts")).unwrap();
        assert_eq!(analyzer.language_id(), "first");
    }

    #[test]
    fn language_registry_lookup_is_idempotent() {
        let mut registry = LanguageRegistry::new();
        registry.register(Box::new(MockAnalyzer::new("typescript", vec!["ts", "tsx"])));

        let first = registry
            .analyzer_for_file(Path::new("component.tsx"))
            .unwrap()
            .language_id()
            .to_string();
        let second = registry
            .analyzer_for_file(Path::new("component.tsx"))
            .unwrap()
            .language_id()
            .to_string();

        assert_eq!(first, second);
        assert_eq!(first, "typescript");
    }

    #[test]
    #[cfg(unix)]
    fn language_registry_handles_non_utf8_extension_without_panicking() {
        let mut registry = LanguageRegistry::new();
        registry.register(Box::new(MockAnalyzer::new("rust", vec!["rs"])));

        let path = PathBuf::from(OsString::from_vec(vec![b'f', b'i', b'l', b'e', b'.', 0xFF]));
        assert!(registry.analyzer_for_file(&path).is_none());
    }
}
