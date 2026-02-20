use crate::client::DaemonClient;
use crate::commands::CommandError;

/// Execute the `conflicts` command, showing overlaps between two workspaces.
pub async fn execute(
    client: &DaemonClient,
    workspace_a: &str,
    workspace_b: &str,
    json: bool,
) -> Result<(), CommandError> {
    let response = client.conflicts(workspace_a, workspace_b).await?;

    if !response.ok {
        let message = response
            .error
            .unwrap_or_else(|| "unknown error".to_string());
        return Err(CommandError::DaemonError(message));
    }

    let data = response.data.unwrap_or_default();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&data).unwrap_or_default()
        );
        return Ok(());
    }

    println!("{}", format_conflicts_output(&data));
    Ok(())
}

/// Format a pair analysis JSON value as plain-text output (extracted for testing).
pub fn format_conflicts_output(data: &serde_json::Value) -> String {
    let mut out = String::new();

    let score = data
        .get("score")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let overlaps = data
        .get("overlaps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let merge_order = data
        .get("merge_order_hint")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");

    out.push_str(&format!("Score: {}\n", format_score(score)));
    out.push_str(&format!(
        "Merge order: {}\n",
        format_merge_order(merge_order)
    ));
    out.push_str(&format!("Overlaps: {}\n", overlaps.len()));
    out.push_str(&"─".repeat(60));
    out.push('\n');

    if overlaps.is_empty() {
        out.push_str("No conflicts detected.\n");
        return out;
    }

    for overlap in &overlaps {
        out.push_str(&format_overlap(overlap));
        out.push('\n');
    }

    out
}

fn format_score(score: &str) -> String {
    match score {
        "Green" => "GREEN (orthogonal)".to_string(),
        "Yellow" => "YELLOW (minor overlap)".to_string(),
        "Red" => "RED (significant conflict)".to_string(),
        "Black" => "BLACK (critical conflict)".to_string(),
        other => other.to_string(),
    }
}

fn format_merge_order(order: &str) -> String {
    match order {
        "AFirst" => "Merge A first".to_string(),
        "BFirst" => "Merge B first".to_string(),
        "Either" => "Either order".to_string(),
        "NeedsCoordination" => "Needs coordination".to_string(),
        other => other.to_string(),
    }
}

fn format_overlap(overlap: &serde_json::Value) -> String {
    // The Overlap enum serializes as a tagged variant via serde.
    // Detect the variant by checking which fields are present.
    if let Some(path) = overlap.get("Hunk") {
        return format_hunk_overlap(path);
    }
    if let Some(sym) = overlap.get("Symbol") {
        return format_symbol_overlap(sym);
    }
    if let Some(dep) = overlap.get("Dependency") {
        return format_dependency_overlap(dep);
    }
    if let Some(schema) = overlap.get("Schema") {
        return format_schema_overlap(schema);
    }
    if let Some(file) = overlap.get("File") {
        return format_file_overlap(file);
    }

    // Fallback: just show the JSON
    format!("  {}", serde_json::to_string(overlap).unwrap_or_default())
}

fn format_file_overlap(data: &serde_json::Value) -> String {
    let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
    let a_change = data.get("a_change").and_then(|v| v.as_str()).unwrap_or("?");
    let b_change = data.get("b_change").and_then(|v| v.as_str()).unwrap_or("?");
    format!("  FILE  {path}  (A: {a_change}, B: {b_change})")
}

fn format_hunk_overlap(data: &serde_json::Value) -> String {
    let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
    let a_start = data
        .get("a_range")
        .and_then(|v| v.get("start"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let a_end = data
        .get("a_range")
        .and_then(|v| v.get("end"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let b_start = data
        .get("b_range")
        .and_then(|v| v.get("start"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let b_end = data
        .get("b_range")
        .and_then(|v| v.get("end"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let distance = data.get("distance").and_then(|v| v.as_u64()).unwrap_or(0);
    format!("  HUNK  {path}  A:[{a_start}-{a_end}] B:[{b_start}-{b_end}] dist={distance}")
}

fn format_symbol_overlap(data: &serde_json::Value) -> String {
    let path = data.get("path").and_then(|v| v.as_str()).unwrap_or("?");
    let name = data
        .get("symbol_name")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let a_mod = data
        .get("a_modification")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let b_mod = data
        .get("b_modification")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    format!("  SYMBOL  {path}::{name}  (A: {a_mod}, B: {b_mod})")
}

fn format_dependency_overlap(data: &serde_json::Value) -> String {
    let changed_file = data
        .get("changed_file")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let affected_file = data
        .get("affected_file")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    format!("  DEP  {changed_file} -> {affected_file}  (export change breaks downstream)")
}

fn format_schema_overlap(data: &serde_json::Value) -> String {
    let category = data.get("category").and_then(|v| v.as_str()).unwrap_or("?");
    let a_file = data.get("a_file").and_then(|v| v.as_str()).unwrap_or("?");
    let b_file = data.get("b_file").and_then(|v| v.as_str()).unwrap_or("?");
    let detail = data.get("detail").and_then(|v| v.as_str()).unwrap_or("");
    format!("  SCHEMA [{category}]  A: {a_file}, B: {b_file}  {detail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_green_score() {
        assert_eq!(format_score("Green"), "GREEN (orthogonal)");
    }

    #[test]
    fn format_yellow_score() {
        assert_eq!(format_score("Yellow"), "YELLOW (minor overlap)");
    }

    #[test]
    fn format_red_score() {
        assert_eq!(format_score("Red"), "RED (significant conflict)");
    }

    #[test]
    fn format_black_score() {
        assert_eq!(format_score("Black"), "BLACK (critical conflict)");
    }

    #[test]
    fn format_unknown_score_passthrough() {
        assert_eq!(format_score("Custom"), "Custom");
    }

    #[test]
    fn format_merge_order_variants() {
        assert_eq!(format_merge_order("AFirst"), "Merge A first");
        assert_eq!(format_merge_order("BFirst"), "Merge B first");
        assert_eq!(format_merge_order("Either"), "Either order");
        assert_eq!(
            format_merge_order("NeedsCoordination"),
            "Needs coordination"
        );
        assert_eq!(format_merge_order("Other"), "Other");
    }

    #[test]
    fn format_conflicts_no_overlaps() {
        let data = serde_json::json!({
            "score": "Green",
            "overlaps": [],
            "merge_order_hint": "Either",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("GREEN (orthogonal)"));
        assert!(output.contains("Either order"));
        assert!(output.contains("Overlaps: 0"));
        assert!(output.contains("No conflicts detected."));
    }

    #[test]
    fn format_conflicts_with_file_overlap() {
        let data = serde_json::json!({
            "score": "Yellow",
            "overlaps": [
                {
                    "File": {
                        "path": "src/auth.ts",
                        "a_change": "Modified",
                        "b_change": "Modified",
                    }
                }
            ],
            "merge_order_hint": "Either",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("YELLOW"));
        assert!(output.contains("Overlaps: 1"));
        assert!(output.contains("FILE  src/auth.ts"));
        assert!(output.contains("A: Modified"));
    }

    #[test]
    fn format_conflicts_with_hunk_overlap() {
        let data = serde_json::json!({
            "score": "Red",
            "overlaps": [
                {
                    "Hunk": {
                        "path": "src/main.rs",
                        "a_range": {"start": 10, "end": 20},
                        "b_range": {"start": 15, "end": 25},
                        "distance": 0,
                    }
                }
            ],
            "merge_order_hint": "AFirst",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("RED"));
        assert!(output.contains("HUNK  src/main.rs"));
        assert!(output.contains("A:[10-20]"));
        assert!(output.contains("B:[15-25]"));
        assert!(output.contains("dist=0"));
    }

    #[test]
    fn format_conflicts_with_symbol_overlap() {
        let data = serde_json::json!({
            "score": "Red",
            "overlaps": [
                {
                    "Symbol": {
                        "path": "src/utils.ts",
                        "symbol_name": "parseConfig",
                        "a_modification": "changed return type",
                        "b_modification": "added parameter",
                    }
                }
            ],
            "merge_order_hint": "NeedsCoordination",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("SYMBOL  src/utils.ts::parseConfig"));
        assert!(output.contains("A: changed return type"));
        assert!(output.contains("B: added parameter"));
        assert!(output.contains("Needs coordination"));
    }

    #[test]
    fn format_conflicts_with_dependency_overlap() {
        let data = serde_json::json!({
            "score": "Black",
            "overlaps": [
                {
                    "Dependency": {
                        "changed_in": "abc-123",
                        "changed_file": "src/api.ts",
                        "changed_export": {"Added": {"name": "foo", "kind": "Function", "range": {"start": 1, "end": 5}, "signature": null}},
                        "affected_file": "src/handler.ts",
                        "affected_usage": [],
                    }
                }
            ],
            "merge_order_hint": "BFirst",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("BLACK"));
        assert!(output.contains("DEP  src/api.ts -> src/handler.ts"));
    }

    #[test]
    fn format_conflicts_with_schema_overlap() {
        let data = serde_json::json!({
            "score": "Yellow",
            "overlaps": [
                {
                    "Schema": {
                        "category": "Migration",
                        "a_file": "migrations/001.sql",
                        "b_file": "migrations/002.sql",
                        "detail": "both add migrations",
                    }
                }
            ],
            "merge_order_hint": "Either",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("SCHEMA [Migration]"));
        assert!(output.contains("migrations/001.sql"));
        assert!(output.contains("both add migrations"));
    }

    #[test]
    fn format_conflicts_with_missing_data() {
        let data = serde_json::json!({});
        let output = format_conflicts_output(&data);
        assert!(output.contains("Score:"));
        assert!(output.contains("No conflicts detected."));
    }

    #[test]
    fn format_conflicts_multiple_overlaps() {
        let data = serde_json::json!({
            "score": "Red",
            "overlaps": [
                {
                    "File": {
                        "path": "a.ts",
                        "a_change": "Modified",
                        "b_change": "Deleted",
                    }
                },
                {
                    "Symbol": {
                        "path": "b.ts",
                        "symbol_name": "doStuff",
                        "a_modification": "renamed",
                        "b_modification": "deleted",
                    }
                }
            ],
            "merge_order_hint": "AFirst",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("Overlaps: 2"));
        assert!(output.contains("FILE  a.ts"));
        assert!(output.contains("SYMBOL  b.ts::doStuff"));
    }

    #[test]
    fn format_conflicts_handles_non_array_overlaps_as_empty() {
        let data = serde_json::json!({
            "score": "Green",
            "overlaps": {"File": {"path": "src/main.rs"}},
            "merge_order_hint": "Either",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("Overlaps: 0"));
        assert!(output.contains("No conflicts detected."));
    }

    #[test]
    fn format_conflicts_falls_back_for_unknown_overlap_shape() {
        let data = serde_json::json!({
            "score": "Yellow",
            "overlaps": [
                {
                    "Custom": {
                        "path": "src/weird.ts",
                        "detail": "unexpected payload"
                    }
                }
            ],
            "merge_order_hint": "Either",
        });
        let output = format_conflicts_output(&data);
        assert!(output.contains("Overlaps: 1"));
        assert!(output.contains(r#""Custom""#));
        assert!(output.contains(r#""path":"src/weird.ts""#));
        assert!(output.contains(r#""detail":"unexpected payload""#));
    }

    #[test]
    fn format_conflicts_overlap_variant_precedence_is_deterministic() {
        let overlap = serde_json::json!({
            "File": {
                "path": "src/a.rs",
                "a_change": "Modified",
                "b_change": "Deleted",
            },
            "Hunk": {
                "path": "src/a.rs",
                "a_range": {"start": 1, "end": 2},
                "b_range": {"start": 3, "end": 4},
                "distance": 0,
            }
        });

        let rendered = format_overlap(&overlap);
        assert!(rendered.contains("HUNK  src/a.rs"));
        assert!(!rendered.contains("FILE  src/a.rs"));
    }

    #[test]
    fn format_conflicts_preserves_overlap_input_order() {
        let data = serde_json::json!({
            "score": "Red",
            "merge_order_hint": "AFirst",
            "overlaps": [
                {
                    "File": {
                        "path": "z-last.ts",
                        "a_change": "Modified",
                        "b_change": "Modified"
                    }
                },
                {
                    "File": {
                        "path": "a-first.ts",
                        "a_change": "Modified",
                        "b_change": "Deleted"
                    }
                }
            ]
        });

        let output = format_conflicts_output(&data);
        let z_idx = output.find("FILE  z-last.ts").unwrap();
        let a_idx = output.find("FILE  a-first.ts").unwrap();
        assert!(z_idx < a_idx);
    }

    #[test]
    fn format_conflicts_with_missing_nested_fields_uses_placeholders() {
        let data = serde_json::json!({
            "score": "Red",
            "overlaps": [
                { "File": {} },
                { "Hunk": { "path": "src/lib.rs" } },
                { "Symbol": { "path": "src/lib.rs" } },
                { "Dependency": {} },
                { "Schema": {} }
            ],
            "merge_order_hint": "NeedsCoordination",
        });

        let output = format_conflicts_output(&data);
        assert!(output.contains("FILE  ?  (A: ?, B: ?)"));
        assert!(output.contains("HUNK  src/lib.rs  A:[0-0] B:[0-0] dist=0"));
        assert!(output.contains("SYMBOL  src/lib.rs::?  (A: ?, B: ?)"));
        assert!(output.contains("DEP  ? -> ?"));
        assert!(output.contains("SCHEMA [?]  A: ?, B: ?"));
    }

    #[test]
    fn format_conflicts_renders_unicode_fields() {
        let data = serde_json::json!({
            "score": "Yellow",
            "overlaps": [
                {
                    "Symbol": {
                        "path": "src/你好.ts",
                        "symbol_name": "λ_transform",
                        "a_modification": "changed 変数",
                        "b_modification": "added 🚀",
                    }
                }
            ],
            "merge_order_hint": "Either",
        });

        let output = format_conflicts_output(&data);
        assert!(output.contains("src/你好.ts::λ_transform"));
        assert!(output.contains("A: changed 変数"));
        assert!(output.contains("B: added 🚀"));
    }
}
