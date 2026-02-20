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
