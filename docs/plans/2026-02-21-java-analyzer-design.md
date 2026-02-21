# Java Language Analyzer Design

## Summary

Add Java language support to `grove-lib` following the established `LanguageAnalyzer` pattern. Uses `tree-sitter-java` for AST parsing with full parity to the Go analyzer: symbol extraction, import detection, export detection, and schema file identification.

## Architecture

Same as existing analyzers: `JavaAnalyzer` struct with `Mutex<Parser>` + `Mutex<Option<ParseCache>>`, implementing the `LanguageAnalyzer` trait. Single file at `crates/grove-lib/src/languages/java.rs`.

## File Extensions

`java`

## Symbol Extraction

Java nests declarations inside `class_declaration`, `interface_declaration`, `enum_declaration`, and `record_declaration` bodies (similar to C#). The analyzer recursively descends into class/interface/enum bodies to extract nested type and member declarations.

| tree-sitter node | SymbolKind |
|---|---|
| `class_declaration` | Class |
| `interface_declaration` | Interface |
| `enum_declaration` | Enum |
| `record_declaration` | Class |
| `annotation_type_declaration` | Interface |
| `method_declaration` | Method |
| `constructor_declaration` | Method |
| `field_declaration` | Variable |
| `constant_declaration` | Constant |

## Import Extraction

`import_declaration` nodes at the top of a file. The source is the fully-qualified package path (e.g., `java.util.List`). Wildcard imports (`java.util.*`) captured as-is. Static imports (`import static org.junit.Assert.assertEquals`) also captured with the `static` prefix stripped from the source path.

## Export Detection

Filter extracted symbols where any `modifiers` child node contains a modifier whose text equals `"public"`. This matches the C# approach and provides the public API surface relevant to cross-worktree conflict detection.

## Schema Files

`pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle.properties`

## Changes

1. Add `tree-sitter-java` to workspace `Cargo.toml` and `crates/grove-lib/Cargo.toml`
2. Create `crates/grove-lib/src/languages/java.rs`
3. Add `pub mod java;` to `mod.rs` and register in `with_defaults()`
