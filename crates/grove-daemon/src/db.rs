use chrono::{DateTime, Utc};
use grove_lib::graph::ImportGraph;
use grove_lib::{
    ChangeType, CommitHash, ExportedSymbol, Hunk, Import, MergeOrder, OrthogonalityScore, Symbol,
    Workspace, WorkspaceId, WorkspaceMetadata, WorkspacePairAnalysis,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("Date parse error: {0}")]
    ChronoParse(#[from] chrono::ParseError),
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, DbError> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    pub fn open_in_memory() -> Result<Self, DbError> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.run_migrations()?;
        Ok(db)
    }

    fn run_migrations(&self) -> Result<(), DbError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                branch TEXT NOT NULL,
                path TEXT NOT NULL,
                base_ref TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_activity TEXT NOT NULL,
                metadata_json TEXT
            );

            CREATE TABLE IF NOT EXISTS base_import_graph (
                file_path TEXT PRIMARY KEY,
                imports_json TEXT NOT NULL,
                exports_json TEXT NOT NULL,
                ast_hash TEXT NOT NULL,
                base_commit TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workspace_graph_deltas (
                workspace_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                delta_type TEXT NOT NULL,
                imports_json TEXT,
                exports_json TEXT,
                ast_hash TEXT NOT NULL,
                PRIMARY KEY (workspace_id, file_path)
            );

            CREATE TABLE IF NOT EXISTS pair_analyses (
                workspace_a TEXT NOT NULL,
                workspace_b TEXT NOT NULL,
                score TEXT NOT NULL,
                overlaps_json TEXT NOT NULL,
                merge_order_hint TEXT,
                computed_at TEXT NOT NULL,
                PRIMARY KEY (workspace_a, workspace_b)
            );

            CREATE TABLE IF NOT EXISTS workspace_files (
                workspace_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                change_type TEXT NOT NULL,
                hunks_json TEXT,
                symbols_json TEXT,
                PRIMARY KEY (workspace_id, file_path)
            );

            CREATE TABLE IF NOT EXISTS base_graph_cache (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                base_commit TEXT NOT NULL,
                graph_json TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    // === Workspace CRUD ===

    pub fn save_workspace(&self, workspace: &Workspace) -> Result<(), DbError> {
        let metadata_json = serde_json::to_string(&workspace.metadata)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO workspaces (id, name, branch, path, base_ref, created_at, last_activity, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                workspace.id.to_string(),
                workspace.name,
                workspace.branch,
                workspace.path.to_string_lossy().to_string(),
                workspace.base_ref,
                workspace.created_at.to_rfc3339(),
                workspace.last_activity.to_rfc3339(),
                metadata_json,
            ],
        )?;
        Ok(())
    }

    pub fn load_workspaces(&self) -> Result<Vec<Workspace>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, branch, path, base_ref, created_at, last_activity, metadata_json
             FROM workspaces",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(WorkspaceRow {
                id: row.get(0)?,
                name: row.get(1)?,
                branch: row.get(2)?,
                path: row.get(3)?,
                base_ref: row.get(4)?,
                created_at: row.get(5)?,
                last_activity: row.get(6)?,
                metadata_json: row.get(7)?,
            })
        })?;

        let mut workspaces = Vec::new();
        for row in rows {
            let row = row?;
            workspaces.push(parse_workspace_row(row)?);
        }
        Ok(workspaces)
    }

    pub fn load_workspace(&self, id: WorkspaceId) -> Result<Option<Workspace>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, branch, path, base_ref, created_at, last_activity, metadata_json
             FROM workspaces WHERE id = ?1",
        )?;

        let row = stmt
            .query_row(params![id.to_string()], |row| {
                Ok(WorkspaceRow {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    branch: row.get(2)?,
                    path: row.get(3)?,
                    base_ref: row.get(4)?,
                    created_at: row.get(5)?,
                    last_activity: row.get(6)?,
                    metadata_json: row.get(7)?,
                })
            })
            .optional()?;

        match row {
            Some(row) => Ok(Some(parse_workspace_row(row)?)),
            None => Ok(None),
        }
    }

    pub fn delete_workspace(&self, id: WorkspaceId) -> Result<(), DbError> {
        let id_str = id.to_string();
        self.conn
            .execute("DELETE FROM workspaces WHERE id = ?1", params![id_str])?;
        self.conn.execute(
            "DELETE FROM workspace_graph_deltas WHERE workspace_id = ?1",
            params![id_str],
        )?;
        self.conn.execute(
            "DELETE FROM workspace_files WHERE workspace_id = ?1",
            params![id_str],
        )?;
        self.conn.execute(
            "DELETE FROM pair_analyses WHERE workspace_a = ?1 OR workspace_b = ?1",
            params![id_str],
        )?;
        Ok(())
    }

    // === Pair Analysis ===

    pub fn save_pair_analysis(&self, analysis: &WorkspacePairAnalysis) -> Result<(), DbError> {
        let overlaps_json = serde_json::to_string(&analysis.overlaps)?;
        let score_str = score_to_str(analysis.score);
        let merge_order_str = merge_order_to_str(analysis.merge_order_hint);
        let mut stmt = self.conn.prepare_cached(
            "INSERT OR REPLACE INTO pair_analyses (workspace_a, workspace_b, score, overlaps_json, merge_order_hint, computed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        stmt.execute(params![
            analysis.workspace_a.to_string(),
            analysis.workspace_b.to_string(),
            score_str,
            overlaps_json,
            merge_order_str,
            analysis.last_computed.to_rfc3339(),
        ])?;
        Ok(())
    }

    pub fn delete_all_pair_analyses(&self) -> Result<(), DbError> {
        self.conn.execute("DELETE FROM pair_analyses", [])?;
        Ok(())
    }

    // === Base Graph Cache ===

    pub fn save_base_graph_cache(
        &self,
        base_commit: &CommitHash,
        graph: &ImportGraph,
    ) -> Result<(), DbError> {
        let graph_json = serde_json::to_string(graph)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO base_graph_cache (id, base_commit, graph_json) VALUES (1, ?1, ?2)",
            params![base_commit, graph_json],
        )?;
        Ok(())
    }

    pub fn load_base_graph_cache(&self) -> Result<Option<(CommitHash, ImportGraph)>, DbError> {
        let mut stmt = self
            .conn
            .prepare("SELECT base_commit, graph_json FROM base_graph_cache WHERE id = 1")?;
        let row: Option<(String, String)> = stmt
            .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        match row {
            Some((base_commit, graph_json)) => {
                let graph: ImportGraph = serde_json::from_str(&graph_json)?;
                Ok(Some((base_commit, graph)))
            }
            None => Ok(None),
        }
    }

    pub fn delete_base_graph_cache(&self) -> Result<(), DbError> {
        self.conn.execute("DELETE FROM base_graph_cache", [])?;
        Ok(())
    }

    pub fn load_pair_analyses(&self) -> Result<Vec<WorkspacePairAnalysis>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT workspace_a, workspace_b, score, overlaps_json, merge_order_hint, computed_at
             FROM pair_analyses",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(PairAnalysisRow {
                workspace_a: row.get(0)?,
                workspace_b: row.get(1)?,
                score: row.get(2)?,
                overlaps_json: row.get(3)?,
                merge_order_hint: row.get(4)?,
                computed_at: row.get(5)?,
            })
        })?;

        let mut analyses = Vec::new();
        for row in rows {
            let row = row?;
            analyses.push(parse_pair_analysis_row(row)?);
        }
        Ok(analyses)
    }

    // === Base Import Graph ===

    pub fn save_base_graph_entry(
        &self,
        file_path: &Path,
        imports: &[Import],
        exports: &[ExportedSymbol],
        ast_hash: &str,
        base_commit: &CommitHash,
    ) -> Result<(), DbError> {
        let imports_json = serde_json::to_string(imports)?;
        let exports_json = serde_json::to_string(exports)?;
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT OR REPLACE INTO base_import_graph (file_path, imports_json, exports_json, ast_hash, base_commit, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                file_path.to_string_lossy().to_string(),
                imports_json,
                exports_json,
                ast_hash,
                base_commit,
                now,
            ],
        )?;
        Ok(())
    }

    pub fn load_base_graph(&self) -> Result<Vec<BaseGraphEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, imports_json, exports_json, ast_hash, base_commit, updated_at
             FROM base_import_graph",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(BaseGraphRow {
                file_path: row.get(0)?,
                imports_json: row.get(1)?,
                exports_json: row.get(2)?,
                ast_hash: row.get(3)?,
                base_commit: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            let row = row?;
            entries.push(BaseGraphEntry {
                file_path: PathBuf::from(&row.file_path),
                imports: serde_json::from_str(&row.imports_json)?,
                exports: serde_json::from_str(&row.exports_json)?,
                ast_hash: row.ast_hash,
                base_commit: row.base_commit,
                updated_at: DateTime::parse_from_rfc3339(&row.updated_at)?.with_timezone(&Utc),
            });
        }
        Ok(entries)
    }

    // === Workspace Graph Deltas ===

    pub fn save_workspace_delta(
        &self,
        workspace_id: WorkspaceId,
        file_path: &Path,
        delta: &WorkspaceDelta,
    ) -> Result<(), DbError> {
        let imports_json = delta
            .imports
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let exports_json = delta
            .exports
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        self.conn.execute(
            "INSERT OR REPLACE INTO workspace_graph_deltas (workspace_id, file_path, delta_type, imports_json, exports_json, ast_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                workspace_id.to_string(),
                file_path.to_string_lossy().to_string(),
                delta_type_to_str(delta.delta_type),
                imports_json,
                exports_json,
                delta.ast_hash,
            ],
        )?;
        Ok(())
    }

    pub fn load_workspace_deltas(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<(PathBuf, WorkspaceDelta)>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, delta_type, imports_json, exports_json, ast_hash
             FROM workspace_graph_deltas WHERE workspace_id = ?1",
        )?;

        let rows = stmt.query_map(params![workspace_id.to_string()], |row| {
            Ok(DeltaRow {
                file_path: row.get(0)?,
                delta_type: row.get(1)?,
                imports_json: row.get(2)?,
                exports_json: row.get(3)?,
                ast_hash: row.get(4)?,
            })
        })?;

        let mut deltas = Vec::new();
        for row in rows {
            let row = row?;
            let imports: Option<Vec<Import>> = row
                .imports_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?;
            let exports: Option<Vec<ExportedSymbol>> = row
                .exports_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()?;

            deltas.push((
                PathBuf::from(&row.file_path),
                WorkspaceDelta {
                    delta_type: delta_type_from_str(&row.delta_type),
                    imports,
                    exports,
                    ast_hash: row.ast_hash,
                },
            ));
        }
        Ok(deltas)
    }

    // === Workspace Files ===

    pub fn save_workspace_file(
        &self,
        workspace_id: WorkspaceId,
        file_path: &Path,
        change_type: ChangeType,
        hunks: &[Hunk],
        symbols: &[Symbol],
    ) -> Result<(), DbError> {
        let hunks_json = serde_json::to_string(hunks)?;
        let symbols_json = serde_json::to_string(symbols)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO workspace_files (workspace_id, file_path, change_type, hunks_json, symbols_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                workspace_id.to_string(),
                file_path.to_string_lossy().to_string(),
                change_type_to_str(change_type),
                hunks_json,
                symbols_json,
            ],
        )?;
        Ok(())
    }

    pub fn load_workspace_files(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<WorkspaceFileEntry>, DbError> {
        let mut stmt = self.conn.prepare(
            "SELECT file_path, change_type, hunks_json, symbols_json
             FROM workspace_files WHERE workspace_id = ?1",
        )?;

        let rows = stmt.query_map(params![workspace_id.to_string()], |row| {
            Ok(WorkspaceFileRow {
                file_path: row.get(0)?,
                change_type: row.get(1)?,
                hunks_json: row.get(2)?,
                symbols_json: row.get(3)?,
            })
        })?;

        let mut files = Vec::new();
        for row in rows {
            let row = row?;
            files.push(WorkspaceFileEntry {
                file_path: PathBuf::from(&row.file_path),
                change_type: change_type_from_str(&row.change_type),
                hunks: serde_json::from_str(&row.hunks_json)?,
                symbols: serde_json::from_str(&row.symbols_json)?,
            });
        }
        Ok(files)
    }
}

// === Data Transfer Types ===

#[derive(Debug, Clone)]
pub struct BaseGraphEntry {
    pub file_path: PathBuf,
    pub imports: Vec<Import>,
    pub exports: Vec<ExportedSymbol>,
    pub ast_hash: String,
    pub base_commit: CommitHash,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceDelta {
    pub delta_type: DeltaType,
    pub imports: Option<Vec<Import>>,
    pub exports: Option<Vec<ExportedSymbol>>,
    pub ast_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaType {
    Modified,
    Added,
    Removed,
}

#[derive(Debug, Clone)]
pub struct WorkspaceFileEntry {
    pub file_path: PathBuf,
    pub change_type: ChangeType,
    pub hunks: Vec<Hunk>,
    pub symbols: Vec<Symbol>,
}

// === Row types for SQLite mapping ===

struct WorkspaceRow {
    id: String,
    name: String,
    branch: String,
    path: String,
    base_ref: String,
    created_at: String,
    last_activity: String,
    metadata_json: Option<String>,
}

struct PairAnalysisRow {
    workspace_a: String,
    workspace_b: String,
    score: String,
    overlaps_json: String,
    merge_order_hint: Option<String>,
    computed_at: String,
}

struct BaseGraphRow {
    file_path: String,
    imports_json: String,
    exports_json: String,
    ast_hash: String,
    base_commit: String,
    updated_at: String,
}

struct DeltaRow {
    file_path: String,
    delta_type: String,
    imports_json: Option<String>,
    exports_json: Option<String>,
    ast_hash: String,
}

struct WorkspaceFileRow {
    file_path: String,
    change_type: String,
    hunks_json: String,
    symbols_json: String,
}

// === Conversion helpers ===

fn parse_workspace_row(row: WorkspaceRow) -> Result<Workspace, DbError> {
    let metadata: WorkspaceMetadata = match row.metadata_json {
        Some(ref json) => serde_json::from_str(json)?,
        None => WorkspaceMetadata::default(),
    };

    Ok(Workspace {
        id: uuid::Uuid::parse_str(&row.id)?,
        name: row.name,
        branch: row.branch,
        path: PathBuf::from(row.path),
        base_ref: row.base_ref,
        created_at: DateTime::parse_from_rfc3339(&row.created_at)?.with_timezone(&Utc),
        last_activity: DateTime::parse_from_rfc3339(&row.last_activity)?.with_timezone(&Utc),
        metadata,
    })
}

fn parse_pair_analysis_row(row: PairAnalysisRow) -> Result<WorkspacePairAnalysis, DbError> {
    Ok(WorkspacePairAnalysis {
        workspace_a: uuid::Uuid::parse_str(&row.workspace_a)?,
        workspace_b: uuid::Uuid::parse_str(&row.workspace_b)?,
        score: score_from_str(&row.score),
        overlaps: serde_json::from_str(&row.overlaps_json)?,
        merge_order_hint: row
            .merge_order_hint
            .as_deref()
            .map(merge_order_from_str)
            .unwrap_or(MergeOrder::Either),
        last_computed: DateTime::parse_from_rfc3339(&row.computed_at)?.with_timezone(&Utc),
    })
}

fn score_to_str(score: OrthogonalityScore) -> &'static str {
    match score {
        OrthogonalityScore::Green => "green",
        OrthogonalityScore::Yellow => "yellow",
        OrthogonalityScore::Red => "red",
        OrthogonalityScore::Black => "black",
    }
}

/// Parses persisted orthogonality score strings from SQLite.
///
/// Unknown values intentionally fall back to a safe default so rows written by
/// newer daemons remain readable by older binaries.
fn score_from_str(s: &str) -> OrthogonalityScore {
    match s {
        "green" => OrthogonalityScore::Green,
        "yellow" => OrthogonalityScore::Yellow,
        "red" => OrthogonalityScore::Red,
        "black" => OrthogonalityScore::Black,
        _ => OrthogonalityScore::Green,
    }
}

fn merge_order_to_str(order: MergeOrder) -> &'static str {
    match order {
        MergeOrder::AFirst => "a_first",
        MergeOrder::BFirst => "b_first",
        MergeOrder::Either => "either",
        MergeOrder::NeedsCoordination => "needs_coordination",
    }
}

/// Parses persisted merge-order strings from SQLite.
///
/// Unknown values intentionally fall back to a safe default so rows written by
/// newer daemons remain readable by older binaries.
fn merge_order_from_str(s: &str) -> MergeOrder {
    match s {
        "a_first" => MergeOrder::AFirst,
        "b_first" => MergeOrder::BFirst,
        "either" => MergeOrder::Either,
        "needs_coordination" => MergeOrder::NeedsCoordination,
        _ => MergeOrder::Either,
    }
}

fn change_type_to_str(ct: ChangeType) -> &'static str {
    match ct {
        ChangeType::Added => "added",
        ChangeType::Modified => "modified",
        ChangeType::Deleted => "deleted",
        ChangeType::Renamed => "renamed",
    }
}

/// Parses persisted change-type strings from SQLite.
///
/// Unknown values intentionally fall back to a safe default so rows written by
/// newer daemons remain readable by older binaries.
fn change_type_from_str(s: &str) -> ChangeType {
    match s {
        "added" => ChangeType::Added,
        "modified" => ChangeType::Modified,
        "deleted" => ChangeType::Deleted,
        "renamed" => ChangeType::Renamed,
        _ => ChangeType::Modified,
    }
}

fn delta_type_to_str(dt: DeltaType) -> &'static str {
    match dt {
        DeltaType::Modified => "modified",
        DeltaType::Added => "added",
        DeltaType::Removed => "removed",
    }
}

/// Parses persisted delta-type strings from SQLite.
///
/// Unknown values intentionally fall back to a safe default so rows written by
/// newer daemons remain readable by older binaries.
fn delta_type_from_str(s: &str) -> DeltaType {
    match s {
        "modified" => DeltaType::Modified,
        "added" => DeltaType::Added,
        "removed" => DeltaType::Removed,
        _ => DeltaType::Modified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grove_lib::{
        ChangeType, ExportedSymbol, Hunk, Import, ImportedSymbol, LineRange, MergeOrder,
        OrthogonalityScore, Overlap, Symbol, SymbolKind,
    };
    use uuid::Uuid;

    fn make_workspace(name: &str) -> Workspace {
        Workspace {
            id: Uuid::new_v4(),
            name: name.to_string(),
            branch: format!("feat/{name}"),
            path: PathBuf::from(format!("/worktrees/{name}")),
            base_ref: "main".to_string(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
            metadata: WorkspaceMetadata {
                description: Some("test workspace".to_string()),
                issue_url: None,
                pr_url: None,
            },
        }
    }

    #[test]
    fn workspace_round_trip() {
        let db = Database::open_in_memory().unwrap();
        let ws = make_workspace("auth-refactor");

        db.save_workspace(&ws).unwrap();
        let loaded = db.load_workspaces().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, ws.id);
        assert_eq!(loaded[0].name, "auth-refactor");
        assert_eq!(loaded[0].branch, "feat/auth-refactor");
        assert_eq!(
            loaded[0].metadata.description,
            Some("test workspace".to_string())
        );
    }

    #[test]
    fn workspace_load_by_id() {
        let db = Database::open_in_memory().unwrap();
        let ws1 = make_workspace("alpha");
        let ws2 = make_workspace("beta");

        db.save_workspace(&ws1).unwrap();
        db.save_workspace(&ws2).unwrap();

        let loaded = db.load_workspace(ws1.id).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "alpha");

        let missing = db.load_workspace(Uuid::new_v4()).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn workspace_delete_cascades() {
        let db = Database::open_in_memory().unwrap();
        let ws = make_workspace("to-delete");

        db.save_workspace(&ws).unwrap();
        db.save_workspace_file(
            ws.id,
            Path::new("src/main.rs"),
            ChangeType::Modified,
            &[],
            &[],
        )
        .unwrap();

        db.delete_workspace(ws.id).unwrap();

        assert!(db.load_workspace(ws.id).unwrap().is_none());
        assert!(db.load_workspace_files(ws.id).unwrap().is_empty());
    }

    #[test]
    fn pair_analysis_round_trip() {
        let db = Database::open_in_memory().unwrap();

        let analysis = WorkspacePairAnalysis {
            workspace_a: Uuid::new_v4(),
            workspace_b: Uuid::new_v4(),
            score: OrthogonalityScore::Red,
            overlaps: vec![
                Overlap::File {
                    path: PathBuf::from("src/auth.ts"),
                    a_change: ChangeType::Modified,
                    b_change: ChangeType::Modified,
                },
                Overlap::Symbol {
                    path: PathBuf::from("src/auth.ts"),
                    symbol_name: "validateToken".to_string(),
                    a_modification: "changed return type".to_string(),
                    b_modification: "added parameter".to_string(),
                },
            ],
            merge_order_hint: MergeOrder::AFirst,
            last_computed: Utc::now(),
        };

        db.save_pair_analysis(&analysis).unwrap();
        let loaded = db.load_pair_analyses().unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].workspace_a, analysis.workspace_a);
        assert_eq!(loaded[0].score, OrthogonalityScore::Red);
        assert_eq!(loaded[0].overlaps.len(), 2);
        assert_eq!(loaded[0].merge_order_hint, MergeOrder::AFirst);
    }

    #[test]
    fn base_graph_round_trip() {
        let db = Database::open_in_memory().unwrap();

        let imports = vec![Import {
            source: "./utils".to_string(),
            symbols: vec![ImportedSymbol {
                name: "formatDate".to_string(),
                alias: None,
            }],
            line: 1,
        }];
        let exports = vec![ExportedSymbol {
            name: "UserService".to_string(),
            kind: SymbolKind::Class,
            signature: None,
        }];

        db.save_base_graph_entry(
            Path::new("src/user.ts"),
            &imports,
            &exports,
            "abc123",
            &"deadbeef".to_string(),
        )
        .unwrap();

        let loaded = db.load_base_graph().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].file_path, PathBuf::from("src/user.ts"));
        assert_eq!(loaded[0].imports.len(), 1);
        assert_eq!(loaded[0].imports[0].source, "./utils");
        assert_eq!(loaded[0].exports.len(), 1);
        assert_eq!(loaded[0].exports[0].name, "UserService");
        assert_eq!(loaded[0].ast_hash, "abc123");
        assert_eq!(loaded[0].base_commit, "deadbeef");
    }

    #[test]
    fn workspace_delta_round_trip() {
        let db = Database::open_in_memory().unwrap();
        let ws_id = Uuid::new_v4();

        let delta = WorkspaceDelta {
            delta_type: DeltaType::Modified,
            imports: Some(vec![Import {
                source: "./new-dep".to_string(),
                symbols: vec![],
                line: 5,
            }]),
            exports: None,
            ast_hash: "modified_hash".to_string(),
        };

        db.save_workspace_delta(ws_id, Path::new("src/lib.ts"), &delta)
            .unwrap();

        let loaded = db.load_workspace_deltas(ws_id).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, PathBuf::from("src/lib.ts"));
        assert_eq!(loaded[0].1.delta_type, DeltaType::Modified);
        assert!(loaded[0].1.imports.is_some());
        assert!(loaded[0].1.exports.is_none());
    }

    #[test]
    fn workspace_files_round_trip() {
        let db = Database::open_in_memory().unwrap();
        let ws_id = Uuid::new_v4();

        let hunks = vec![Hunk {
            old_start: 10,
            old_lines: 5,
            new_start: 10,
            new_lines: 8,
        }];
        let symbols = vec![Symbol {
            name: "processPayment".to_string(),
            kind: SymbolKind::Function,
            range: LineRange { start: 10, end: 18 },
            signature: Some("fn processPayment(amount: f64) -> Result".to_string()),
        }];

        db.save_workspace_file(
            ws_id,
            Path::new("src/payment.rs"),
            ChangeType::Modified,
            &hunks,
            &symbols,
        )
        .unwrap();

        let loaded = db.load_workspace_files(ws_id).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].file_path, PathBuf::from("src/payment.rs"));
        assert_eq!(loaded[0].change_type, ChangeType::Modified);
        assert_eq!(loaded[0].hunks.len(), 1);
        assert_eq!(loaded[0].hunks[0].new_lines, 8);
        assert_eq!(loaded[0].symbols.len(), 1);
        assert_eq!(loaded[0].symbols[0].name, "processPayment");
    }

    #[test]
    fn workspace_upsert_overwrites() {
        let db = Database::open_in_memory().unwrap();
        let mut ws = make_workspace("evolving");

        db.save_workspace(&ws).unwrap();

        ws.branch = "feat/evolved".to_string();
        ws.metadata.description = Some("updated".to_string());
        db.save_workspace(&ws).unwrap();

        let loaded = db.load_workspaces().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].branch, "feat/evolved");
        assert_eq!(loaded[0].metadata.description, Some("updated".to_string()));
    }

    #[test]
    fn corrupted_workspace_metadata_json_returns_error() {
        let db = Database::open_in_memory().unwrap();
        let ws = make_workspace("corrupt-metadata");
        db.save_workspace(&ws).unwrap();

        db.conn
            .execute(
                "UPDATE workspaces SET metadata_json = '{\"description\":' WHERE id = ?1",
                rusqlite::params![ws.id.to_string()],
            )
            .unwrap();

        let result = db.load_workspace(ws.id);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DbError::Json(_)));
    }

    #[test]
    fn corrupted_pair_analysis_overlaps_json_returns_error() {
        let db = Database::open_in_memory().unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let analysis = WorkspacePairAnalysis {
            workspace_a: a,
            workspace_b: b,
            score: OrthogonalityScore::Yellow,
            overlaps: vec![],
            merge_order_hint: MergeOrder::Either,
            last_computed: Utc::now(),
        };
        db.save_pair_analysis(&analysis).unwrap();

        db.conn
            .execute(
                "UPDATE pair_analyses SET overlaps_json = '[{\"invalid\":]' WHERE workspace_a = ?1 AND workspace_b = ?2",
                rusqlite::params![a.to_string(), b.to_string()],
            )
            .unwrap();

        let result = db.load_pair_analyses();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DbError::Json(_)));
    }

    #[test]
    fn malformed_workspace_uuid_row_returns_uuid_error() {
        let db = Database::open_in_memory().unwrap();
        let now = Utc::now().to_rfc3339();
        db.conn
            .execute(
                "INSERT INTO workspaces (id, name, branch, path, base_ref, created_at, last_activity, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    "not-a-uuid",
                    "bad-row",
                    "feat/bad-row",
                    "/tmp/bad-row",
                    "main",
                    now,
                    Utc::now().to_rfc3339(),
                    "{\"description\":null,\"issue_url\":null,\"pr_url\":null}"
                ],
            )
            .unwrap();

        let err = db
            .load_workspaces()
            .expect_err("expected UUID parse failure");
        assert!(matches!(err, DbError::Uuid(_)));
    }

    #[test]
    fn malformed_workspace_timestamp_row_returns_chrono_error() {
        let db = Database::open_in_memory().unwrap();
        db.conn
            .execute(
                "INSERT INTO workspaces (id, name, branch, path, base_ref, created_at, last_activity, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    "bad-ts",
                    "feat/bad-ts",
                    "/tmp/bad-ts",
                    "main",
                    "not-a-timestamp",
                    Utc::now().to_rfc3339(),
                    "{\"description\":null,\"issue_url\":null,\"pr_url\":null}"
                ],
            )
            .unwrap();

        let err = db
            .load_workspaces()
            .expect_err("expected date parse failure");
        assert!(matches!(err, DbError::ChronoParse(_)));
    }

    #[test]
    fn unknown_pair_analysis_enum_values_fallback_to_safe_defaults() {
        let db = Database::open_in_memory().unwrap();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        db.conn
            .execute(
                "INSERT INTO pair_analyses (workspace_a, workspace_b, score, overlaps_json, merge_order_hint, computed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    a.to_string(),
                    b.to_string(),
                    "not-a-known-score",
                    "[]",
                    "not-a-known-order",
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();

        let analyses = db.load_pair_analyses().unwrap();
        assert_eq!(analyses.len(), 1);
        assert_eq!(analyses[0].score, OrthogonalityScore::Green);
        assert_eq!(analyses[0].merge_order_hint, MergeOrder::Either);
    }

    #[test]
    fn malformed_pair_analysis_timestamp_returns_chrono_error() {
        let db = Database::open_in_memory().unwrap();
        db.conn
            .execute(
                "INSERT INTO pair_analyses (workspace_a, workspace_b, score, overlaps_json, merge_order_hint, computed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    "yellow",
                    "[]",
                    "either",
                    "definitely-not-rfc3339"
                ],
            )
            .unwrap();

        let err = db
            .load_pair_analyses()
            .expect_err("expected computed_at parse failure");
        assert!(matches!(err, DbError::ChronoParse(_)));
    }

    #[test]
    fn malformed_base_graph_json_row_returns_error() {
        let db = Database::open_in_memory().unwrap();
        db.conn
            .execute(
                "INSERT INTO base_import_graph (file_path, imports_json, exports_json, ast_hash, base_commit, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    "src/bad.ts",
                    "[{\"source\":]",
                    "[]",
                    "hash",
                    "base",
                    Utc::now().to_rfc3339()
                ],
            )
            .unwrap();

        let err = db
            .load_base_graph()
            .expect_err("expected JSON parse failure");
        assert!(matches!(err, DbError::Json(_)));
    }

    #[test]
    fn malformed_workspace_delta_json_row_returns_error() {
        let db = Database::open_in_memory().unwrap();
        let ws_id = Uuid::new_v4();
        db.conn
            .execute(
                "INSERT INTO workspace_graph_deltas (workspace_id, file_path, delta_type, imports_json, exports_json, ast_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    ws_id.to_string(),
                    "src/delta.ts",
                    "modified",
                    "[]",
                    "{\"broken\":",
                    "hash"
                ],
            )
            .unwrap();

        let err = db
            .load_workspace_deltas(ws_id)
            .expect_err("expected JSON parse failure");
        assert!(matches!(err, DbError::Json(_)));
    }

    #[test]
    fn malformed_workspace_file_symbols_json_row_returns_error() {
        let db = Database::open_in_memory().unwrap();
        let ws_id = Uuid::new_v4();
        db.conn
            .execute(
                "INSERT INTO workspace_files (workspace_id, file_path, change_type, hunks_json, symbols_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    ws_id.to_string(),
                    "src/main.rs",
                    "modified",
                    "[]",
                    "[{\"name\":]"
                ],
            )
            .unwrap();

        let err = db
            .load_workspace_files(ws_id)
            .expect_err("expected JSON parse failure");
        assert!(matches!(err, DbError::Json(_)));
    }
}
