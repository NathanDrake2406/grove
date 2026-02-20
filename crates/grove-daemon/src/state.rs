use grove_lib::graph::{GraphOverlay, ImportGraph};
use grove_lib::{CommitHash, Workspace, WorkspaceId, WorkspacePairAnalysis};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::db::Database;

// === Configuration ===

#[derive(Debug, Clone)]
pub struct GroveConfig {
    pub base_branch: String,
    pub watch_interval_ms: u64,
    pub max_warm_asts: usize,
    pub max_worktrees: usize,
    pub analysis_timeout_ms: u64,
    pub socket_idle_timeout_ms: u64,
    pub socket_state_reply_timeout_ms: u64,
    pub max_file_size_kb: u64,
    pub circuit_breaker_threshold: usize,
    pub ignore_patterns: Vec<String>,
    pub respect_gitignore: bool,
}

impl Default for GroveConfig {
    fn default() -> Self {
        Self {
            base_branch: "main".to_string(),
            watch_interval_ms: 500,
            max_warm_asts: 5000,
            max_worktrees: 20,
            analysis_timeout_ms: 30_000,
            socket_idle_timeout_ms: 300_000,
            socket_state_reply_timeout_ms: 5_000,
            max_file_size_kb: 1024,
            circuit_breaker_threshold: 100,
            ignore_patterns: vec![
                "node_modules".to_string(),
                "target".to_string(),
                "dist".to_string(),
                "build".to_string(),
                ".git/objects".to_string(),
                ".git/lfs".to_string(),
                "*.min.js".to_string(),
                "*.map".to_string(),
            ],
            respect_gitignore: true,
        }
    }
}

// === State Messages ===

pub enum StateMessage {
    FileChanged {
        workspace_id: WorkspaceId,
        path: PathBuf,
    },
    AnalysisComplete {
        pair: (WorkspaceId, WorkspaceId),
        result: WorkspacePairAnalysis,
    },
    Query {
        request: QueryRequest,
        reply: oneshot::Sender<QueryResponse>,
    },
    BaseRefChanged {
        new_commit: CommitHash,
    },
    WorktreeReindexComplete {
        workspace_id: WorkspaceId,
        overlay: GraphOverlay,
    },
    RegisterWorkspace {
        workspace: Workspace,
        reply: oneshot::Sender<Result<(), String>>,
    },
    RemoveWorkspace {
        workspace_id: WorkspaceId,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum QueryRequest {
    ListWorkspaces,
    GetWorkspace {
        workspace_id: WorkspaceId,
    },
    GetPairAnalysis {
        workspace_a: WorkspaceId,
        workspace_b: WorkspaceId,
    },
    GetAllAnalyses,
    GetStatus,
}

#[derive(Debug, Clone)]
pub enum QueryResponse {
    Workspaces(Vec<Workspace>),
    Workspace(Option<Workspace>),
    PairAnalysis(Option<WorkspacePairAnalysis>),
    AllAnalyses(Vec<WorkspacePairAnalysis>),
    Status {
        workspace_count: usize,
        analysis_count: usize,
        base_commit: CommitHash,
    },
}

// === Daemon State ===

pub struct DaemonState {
    config: GroveConfig,
    workspaces: HashMap<WorkspaceId, Workspace>,
    #[allow(dead_code)] // Used when worker system is wired up
    base_graph: ImportGraph,
    base_commit: CommitHash,
    workspace_overlays: HashMap<WorkspaceId, GraphOverlay>,
    pair_analyses: HashMap<(WorkspaceId, WorkspaceId), WorkspacePairAnalysis>,
    dirty_workspaces: Vec<WorkspaceId>,
    db: Option<Database>,
}

impl DaemonState {
    pub fn new(config: GroveConfig, db: Option<Database>) -> Self {
        Self {
            config,
            workspaces: HashMap::new(),
            base_graph: ImportGraph::new(),
            base_commit: String::new(),
            workspace_overlays: HashMap::new(),
            pair_analyses: HashMap::new(),
            dirty_workspaces: Vec::new(),
            db,
        }
    }

    pub fn with_persisted_state(mut self) -> Self {
        if let Some(ref db) = self.db {
            match db.load_workspaces() {
                Ok(workspaces) => {
                    for ws in workspaces {
                        self.workspaces.insert(ws.id, ws);
                    }
                    info!(count = self.workspaces.len(), "loaded workspaces from db");
                }
                Err(e) => {
                    warn!(error = %e, "failed to load workspaces from db");
                }
            }

            match db.load_pair_analyses() {
                Ok(analyses) => {
                    for a in analyses {
                        self.pair_analyses.insert((a.workspace_a, a.workspace_b), a);
                    }
                    info!(
                        count = self.pair_analyses.len(),
                        "loaded pair analyses from db"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "failed to load pair analyses from db");
                }
            }
        }
        self
    }

    /// Run the actor loop until Shutdown is received.
    ///
    /// Once shutdown starts, the receiver is closed to reject new sends, then
    /// queued messages are drained. Queued queries are still answered so
    /// in-flight request/response paths do not hang while the daemon exits.
    pub async fn run(mut self, mut rx: mpsc::Receiver<StateMessage>) {
        info!("state actor started");

        while let Some(msg) = rx.recv().await {
            let shutdown_requested = match msg {
                StateMessage::FileChanged { workspace_id, path } => {
                    self.handle_file_changed(workspace_id, &path);
                    false
                }
                StateMessage::AnalysisComplete { pair, result } => {
                    self.handle_analysis_complete(pair, result);
                    false
                }
                StateMessage::Query { request, reply } => {
                    let response = self.handle_query(request);
                    if reply.send(response).is_err() {
                        debug!("query reply channel dropped");
                    }
                    false
                }
                StateMessage::BaseRefChanged { new_commit } => {
                    self.handle_base_ref_changed(new_commit);
                    false
                }
                StateMessage::WorktreeReindexComplete {
                    workspace_id,
                    overlay,
                } => {
                    self.handle_worktree_reindex_complete(workspace_id, overlay);
                    false
                }
                StateMessage::RegisterWorkspace { workspace, reply } => {
                    let result = self.handle_register_workspace(workspace);
                    if reply.send(result).is_err() {
                        debug!("register reply channel dropped");
                    }
                    false
                }
                StateMessage::RemoveWorkspace {
                    workspace_id,
                    reply,
                } => {
                    let result = self.handle_remove_workspace(workspace_id);
                    if reply.send(result).is_err() {
                        debug!("remove reply channel dropped");
                    }
                    false
                }
                StateMessage::Shutdown => {
                    info!("state actor shutting down");
                    true
                }
            };

            if shutdown_requested {
                rx.close();
                self.drain_queued_messages(&mut rx).await;
                break;
            }
        }

        info!("state actor stopped");
    }

    async fn drain_queued_messages(&mut self, rx: &mut mpsc::Receiver<StateMessage>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                StateMessage::Query { request, reply } => {
                    let response = self.handle_query(request);
                    if reply.send(response).is_err() {
                        debug!("query reply channel dropped during shutdown drain");
                    }
                }
                StateMessage::RegisterWorkspace { reply, .. } => {
                    if reply
                        .send(Err("daemon is shutting down".to_string()))
                        .is_err()
                    {
                        debug!("register reply channel dropped during shutdown drain");
                    }
                }
                StateMessage::RemoveWorkspace { reply, .. } => {
                    if reply
                        .send(Err("daemon is shutting down".to_string()))
                        .is_err()
                    {
                        debug!("remove reply channel dropped during shutdown drain");
                    }
                }
                StateMessage::FileChanged { .. }
                | StateMessage::AnalysisComplete { .. }
                | StateMessage::BaseRefChanged { .. }
                | StateMessage::WorktreeReindexComplete { .. } => {
                    debug!("dropping state mutation queued after shutdown");
                }
                StateMessage::Shutdown => {
                    debug!("dropping duplicate shutdown message");
                }
            }
        }
    }

    // === Message Handlers ===

    fn handle_file_changed(&mut self, workspace_id: WorkspaceId, path: &Path) {
        if !self.workspaces.contains_key(&workspace_id) {
            warn!(workspace_id = %workspace_id, "file change for unknown workspace");
            return;
        }

        debug!(workspace_id = %workspace_id, path = %path.display(), "file changed");

        if !self.dirty_workspaces.contains(&workspace_id) {
            self.dirty_workspaces.push(workspace_id);
        }
    }

    fn handle_analysis_complete(
        &mut self,
        pair: (WorkspaceId, WorkspaceId),
        result: WorkspacePairAnalysis,
    ) {
        info!(
            workspace_a = %pair.0,
            workspace_b = %pair.1,
            score = ?result.score,
            overlaps = result.overlaps.len(),
            "analysis complete"
        );

        if let Some(ref db) = self.db
            && let Err(e) = db.save_pair_analysis(&result)
        {
            error!(error = %e, "failed to persist pair analysis");
        }

        self.pair_analyses.insert(pair, result);
    }

    fn handle_query(&self, request: QueryRequest) -> QueryResponse {
        match request {
            QueryRequest::ListWorkspaces => {
                let workspaces: Vec<Workspace> = self.workspaces.values().cloned().collect();
                QueryResponse::Workspaces(workspaces)
            }
            QueryRequest::GetWorkspace { workspace_id } => {
                QueryResponse::Workspace(self.workspaces.get(&workspace_id).cloned())
            }
            QueryRequest::GetPairAnalysis {
                workspace_a,
                workspace_b,
            } => {
                let analysis = self
                    .pair_analyses
                    .get(&(workspace_a, workspace_b))
                    .or_else(|| self.pair_analyses.get(&(workspace_b, workspace_a)))
                    .cloned();
                QueryResponse::PairAnalysis(analysis)
            }
            QueryRequest::GetAllAnalyses => {
                let analyses: Vec<WorkspacePairAnalysis> =
                    self.pair_analyses.values().cloned().collect();
                QueryResponse::AllAnalyses(analyses)
            }
            QueryRequest::GetStatus => QueryResponse::Status {
                workspace_count: self.workspaces.len(),
                analysis_count: self.pair_analyses.len(),
                base_commit: self.base_commit.clone(),
            },
        }
    }

    fn handle_base_ref_changed(&mut self, new_commit: CommitHash) {
        if new_commit == self.base_commit {
            debug!("base ref unchanged, skipping rebuild");
            return;
        }

        info!(
            old_commit = %self.base_commit,
            new_commit = %new_commit,
            "base ref changed, will rebuild base graph"
        );

        self.base_commit = new_commit;
        // Full base graph rebuild will be triggered by the watcher/worker.
        // Clear stale analyses since they reference the old base.
        self.pair_analyses.clear();
        self.workspace_overlays.clear();
    }

    fn handle_worktree_reindex_complete(
        &mut self,
        workspace_id: WorkspaceId,
        overlay: GraphOverlay,
    ) {
        info!(workspace_id = %workspace_id, "worktree reindex complete");
        self.workspace_overlays.insert(workspace_id, overlay);
        self.dirty_workspaces.retain(|id| *id != workspace_id);
    }

    fn handle_register_workspace(&mut self, workspace: Workspace) -> Result<(), String> {
        if self.workspaces.len() >= self.config.max_worktrees {
            return Err(format!(
                "maximum worktree limit ({}) reached",
                self.config.max_worktrees
            ));
        }

        let id = workspace.id;
        info!(workspace_id = %id, name = %workspace.name, "registering workspace");

        if let Some(ref db) = self.db
            && let Err(e) = db.save_workspace(&workspace)
        {
            error!(error = %e, "failed to persist workspace");
            return Err(format!("persistence error: {e}"));
        }

        self.workspaces.insert(id, workspace);
        Ok(())
    }

    fn handle_remove_workspace(&mut self, workspace_id: WorkspaceId) -> Result<(), String> {
        if self.workspaces.remove(&workspace_id).is_none() {
            return Err(format!("workspace {workspace_id} not found"));
        }

        info!(workspace_id = %workspace_id, "removing workspace");

        self.workspace_overlays.remove(&workspace_id);
        self.dirty_workspaces.retain(|id| *id != workspace_id);

        // Remove all pair analyses involving this workspace
        self.pair_analyses
            .retain(|(a, b), _| *a != workspace_id && *b != workspace_id);

        if let Some(ref db) = self.db
            && let Err(e) = db.delete_workspace(workspace_id)
        {
            error!(error = %e, "failed to delete workspace from db");
        }

        Ok(())
    }

    // === Accessors (for testing) ===

    pub fn workspace_count(&self) -> usize {
        self.workspaces.len()
    }

    pub fn analysis_count(&self) -> usize {
        self.pair_analyses.len()
    }

    pub fn base_commit(&self) -> &str {
        &self.base_commit
    }

    pub fn dirty_workspaces(&self) -> &[WorkspaceId] {
        &self.dirty_workspaces
    }
}

/// Create a state actor and return the sender handle.
pub fn spawn_state_actor(
    config: GroveConfig,
    db: Option<Database>,
) -> (mpsc::Sender<StateMessage>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(256);
    let state = DaemonState::new(config, db).with_persisted_state();
    let handle = tokio::spawn(state.run(rx));
    (tx, handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use grove_lib::{MergeOrder, OrthogonalityScore, WorkspaceMetadata};
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
            metadata: WorkspaceMetadata::default(),
        }
    }

    #[tokio::test]
    async fn register_and_query_workspace() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        let ws = make_workspace("auth-refactor");
        let ws_id = ws.id;

        // Register
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: ws,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Query
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetWorkspace {
                workspace_id: ws_id,
            },
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::Workspace(Some(ws)) => {
                assert_eq!(ws.name, "auth-refactor");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn list_workspaces() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        for name in &["alpha", "beta", "gamma"] {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(StateMessage::RegisterWorkspace {
                workspace: make_workspace(name),
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx.await.unwrap().unwrap();
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::ListWorkspaces,
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::Workspaces(ws) => assert_eq!(ws.len(), 3),
            other => panic!("unexpected response: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn remove_workspace_cleans_up() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        let ws = make_workspace("to-remove");
        let ws_id = ws.id;

        // Register
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: ws,
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap().unwrap();

        // Remove
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::RemoveWorkspace {
            workspace_id: ws_id,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Verify gone
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetWorkspace {
                workspace_id: ws_id,
            },
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::Workspace(None) => {}
            other => panic!("expected None, got: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn file_changed_marks_dirty() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        let ws = make_workspace("active");
        let ws_id = ws.id;

        // Register
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: ws,
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap().unwrap();

        // File change
        tx.send(StateMessage::FileChanged {
            workspace_id: ws_id,
            path: PathBuf::from("src/main.rs"),
        })
        .await
        .unwrap();

        // Query status to confirm actor processed the message
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetStatus,
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::Status {
                workspace_count, ..
            } => assert_eq!(workspace_count, 1),
            other => panic!("unexpected: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn analysis_complete_stores_result() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        let ws_a = make_workspace("a");
        let ws_b = make_workspace("b");
        let id_a = ws_a.id;
        let id_b = ws_b.id;

        // Register both
        for ws in [ws_a, ws_b] {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(StateMessage::RegisterWorkspace {
                workspace: ws,
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx.await.unwrap().unwrap();
        }

        // Send analysis result
        let analysis = WorkspacePairAnalysis {
            workspace_a: id_a,
            workspace_b: id_b,
            score: OrthogonalityScore::Yellow,
            overlaps: vec![],
            merge_order_hint: MergeOrder::Either,
            last_computed: Utc::now(),
        };
        tx.send(StateMessage::AnalysisComplete {
            pair: (id_a, id_b),
            result: analysis,
        })
        .await
        .unwrap();

        // Query it back
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetPairAnalysis {
                workspace_a: id_a,
                workspace_b: id_b,
            },
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::PairAnalysis(Some(a)) => {
                assert_eq!(a.score, OrthogonalityScore::Yellow);
            }
            other => panic!("expected analysis, got: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn base_ref_change_clears_analyses() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        let ws_a = make_workspace("a");
        let ws_b = make_workspace("b");
        let id_a = ws_a.id;
        let id_b = ws_b.id;

        for ws in [ws_a, ws_b] {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(StateMessage::RegisterWorkspace {
                workspace: ws,
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx.await.unwrap().unwrap();
        }

        // Add an analysis
        tx.send(StateMessage::AnalysisComplete {
            pair: (id_a, id_b),
            result: WorkspacePairAnalysis {
                workspace_a: id_a,
                workspace_b: id_b,
                score: OrthogonalityScore::Green,
                overlaps: vec![],
                merge_order_hint: MergeOrder::Either,
                last_computed: Utc::now(),
            },
        })
        .await
        .unwrap();

        // Base ref changes → analyses cleared
        tx.send(StateMessage::BaseRefChanged {
            new_commit: "new-abc123".to_string(),
        })
        .await
        .unwrap();

        // Query — should be gone
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetAllAnalyses,
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::AllAnalyses(analyses) => assert!(analyses.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn max_worktrees_enforced() {
        let config = GroveConfig {
            max_worktrees: 2,
            ..GroveConfig::default()
        };
        let (tx, handle) = spawn_state_actor(config, None);

        for name in &["a", "b"] {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(StateMessage::RegisterWorkspace {
                workspace: make_workspace(name),
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx.await.unwrap().unwrap();
        }

        // Third should fail
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: make_workspace("c"),
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_err());

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rapid_register_and_query_all_responses_arrive() {
        let config = GroveConfig {
            max_worktrees: 200,
            ..GroveConfig::default()
        };
        let (tx, handle) = spawn_state_actor(config, None);

        let mut tasks = Vec::new();
        for i in 0..100 {
            let tx_cloned = tx.clone();
            tasks.push(tokio::spawn(async move {
                let ws = make_workspace(&format!("ws-{i:03}"));
                let ws_id = ws.id;

                let (reg_reply_tx, reg_reply_rx) = oneshot::channel();
                tx_cloned
                    .send(StateMessage::RegisterWorkspace {
                        workspace: ws,
                        reply: reg_reply_tx,
                    })
                    .await
                    .unwrap();
                assert!(reg_reply_rx.await.unwrap().is_ok());

                let (query_reply_tx, query_reply_rx) = oneshot::channel();
                tx_cloned
                    .send(StateMessage::Query {
                        request: QueryRequest::GetWorkspace {
                            workspace_id: ws_id,
                        },
                        reply: query_reply_tx,
                    })
                    .await
                    .unwrap();

                match query_reply_rx.await.unwrap() {
                    QueryResponse::Workspace(Some(found)) => assert_eq!(found.id, ws_id),
                    other => panic!("unexpected query response: {other:?}"),
                }
            }));
        }

        for task in tasks {
            task.await.unwrap();
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::ListWorkspaces,
            reply: reply_tx,
        })
        .await
        .unwrap();
        match reply_rx.await.unwrap() {
            QueryResponse::Workspaces(workspaces) => assert_eq!(workspaces.len(), 100),
            other => panic!("unexpected response: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn register_then_remove_same_workspace_immediately() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);
        let ws = make_workspace("quick-remove");
        let ws_id = ws.id;

        let (reg_reply_tx, reg_reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: ws,
            reply: reg_reply_tx,
        })
        .await
        .unwrap();

        let (remove_reply_tx, remove_reply_rx) = oneshot::channel();
        tx.send(StateMessage::RemoveWorkspace {
            workspace_id: ws_id,
            reply: remove_reply_tx,
        })
        .await
        .unwrap();

        assert!(reg_reply_rx.await.unwrap().is_ok());
        assert!(remove_reply_rx.await.unwrap().is_ok());

        let (query_reply_tx, query_reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetWorkspace {
                workspace_id: ws_id,
            },
            reply: query_reply_tx,
        })
        .await
        .unwrap();
        assert!(matches!(
            query_reply_rx.await.unwrap(),
            QueryResponse::Workspace(None)
        ));

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_after_remove_message_returns_none() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);
        let ws = make_workspace("remove-query");
        let ws_id = ws.id;

        let (reg_reply_tx, reg_reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: ws,
            reply: reg_reply_tx,
        })
        .await
        .unwrap();
        reg_reply_rx.await.unwrap().unwrap();

        let (remove_reply_tx, remove_reply_rx) = oneshot::channel();
        tx.send(StateMessage::RemoveWorkspace {
            workspace_id: ws_id,
            reply: remove_reply_tx,
        })
        .await
        .unwrap();
        remove_reply_rx.await.unwrap().unwrap();

        let (query_reply_tx, query_reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetWorkspace {
                workspace_id: ws_id,
            },
            reply: query_reply_tx,
        })
        .await
        .unwrap();
        assert!(matches!(
            query_reply_rx.await.unwrap(),
            QueryResponse::Workspace(None)
        ));

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn get_pair_analysis_query_is_order_insensitive() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);
        let ws_a = make_workspace("pair-a");
        let ws_b = make_workspace("pair-b");
        let id_a = ws_a.id;
        let id_b = ws_b.id;

        for ws in [ws_a, ws_b] {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(StateMessage::RegisterWorkspace {
                workspace: ws,
                reply: reply_tx,
            })
            .await
            .unwrap();
            reply_rx.await.unwrap().unwrap();
        }

        let analysis = WorkspacePairAnalysis {
            workspace_a: id_a,
            workspace_b: id_b,
            score: OrthogonalityScore::Red,
            overlaps: vec![],
            merge_order_hint: MergeOrder::NeedsCoordination,
            last_computed: Utc::now(),
        };
        tx.send(StateMessage::AnalysisComplete {
            pair: (id_a, id_b),
            result: analysis,
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetPairAnalysis {
                workspace_a: id_b,
                workspace_b: id_a,
            },
            reply: reply_tx,
        })
        .await
        .unwrap();

        match reply_rx.await.unwrap() {
            QueryResponse::PairAnalysis(Some(found)) => {
                assert_eq!(found.workspace_a, id_a);
                assert_eq!(found.workspace_b, id_b);
                assert_eq!(found.score, OrthogonalityScore::Red);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[test]
    fn duplicate_file_changed_messages_do_not_duplicate_dirty_workspace() {
        let mut state = DaemonState::new(GroveConfig::default(), None);
        let ws = make_workspace("dup-dirty");
        let ws_id = ws.id;
        state.handle_register_workspace(ws).unwrap();

        state.handle_file_changed(ws_id, Path::new("src/a.rs"));
        state.handle_file_changed(ws_id, Path::new("src/b.rs"));
        state.handle_file_changed(ws_id, Path::new("src/c.rs"));

        assert_eq!(state.dirty_workspaces().len(), 1);
        assert_eq!(state.dirty_workspaces()[0], ws_id);
    }

    #[test]
    fn file_changed_for_unknown_workspace_is_ignored() {
        let mut state = DaemonState::new(GroveConfig::default(), None);
        state.handle_file_changed(Uuid::new_v4(), Path::new("src/ghost.rs"));
        assert!(state.dirty_workspaces().is_empty());
    }

    #[test]
    fn removing_unknown_workspace_returns_error_without_side_effects() {
        let mut state = DaemonState::new(GroveConfig::default(), None);
        state
            .handle_register_workspace(make_workspace("still-here"))
            .unwrap();
        assert_eq!(state.workspace_count(), 1);

        let err = state
            .handle_remove_workspace(Uuid::new_v4())
            .expect_err("unknown workspace should fail");
        assert!(err.contains("not found"));
        assert_eq!(state.workspace_count(), 1);
    }

    #[test]
    fn base_ref_same_commit_does_not_clear_analyses() {
        let mut state = DaemonState::new(GroveConfig::default(), None);
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        state.handle_base_ref_changed("base-123".to_string());
        state.handle_analysis_complete(
            (id_a, id_b),
            WorkspacePairAnalysis {
                workspace_a: id_a,
                workspace_b: id_b,
                score: OrthogonalityScore::Yellow,
                overlaps: vec![],
                merge_order_hint: MergeOrder::Either,
                last_computed: Utc::now(),
            },
        );
        assert_eq!(state.analysis_count(), 1);

        state.handle_base_ref_changed("base-123".to_string());
        assert_eq!(state.analysis_count(), 1);
        assert_eq!(state.base_commit(), "base-123");
    }

    #[tokio::test]
    async fn dropped_query_reply_channel_does_not_break_actor() {
        let (tx, handle) = spawn_state_actor(GroveConfig::default(), None);

        let (dropped_reply_tx, dropped_reply_rx) = oneshot::channel();
        drop(dropped_reply_rx);
        tx.send(StateMessage::Query {
            request: QueryRequest::GetStatus,
            reply: dropped_reply_tx,
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetStatus,
            reply: reply_tx,
        })
        .await
        .unwrap();
        match reply_rx.await.unwrap() {
            QueryResponse::Status {
                workspace_count,
                analysis_count,
                ..
            } => {
                assert_eq!(workspace_count, 0);
                assert_eq!(analysis_count, 0);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_file_change_burst_keeps_actor_responsive() {
        let (tx, handle) = spawn_state_actor(
            GroveConfig {
                max_worktrees: 5,
                ..GroveConfig::default()
            },
            None,
        );
        let ws = make_workspace("burst");
        let ws_id = ws.id;

        let (register_reply_tx, register_reply_rx) = oneshot::channel();
        tx.send(StateMessage::RegisterWorkspace {
            workspace: ws,
            reply: register_reply_tx,
        })
        .await
        .unwrap();
        register_reply_rx.await.unwrap().unwrap();

        let mut tasks = Vec::new();
        for i in 0..256 {
            let tx_cloned = tx.clone();
            tasks.push(tokio::spawn(async move {
                tx_cloned
                    .send(StateMessage::FileChanged {
                        workspace_id: ws_id,
                        path: PathBuf::from(format!("src/{i}.rs")),
                    })
                    .await
                    .unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(StateMessage::Query {
            request: QueryRequest::GetStatus,
            reply: reply_tx,
        })
        .await
        .unwrap();
        match reply_rx.await.unwrap() {
            QueryResponse::Status {
                workspace_count,
                analysis_count,
                ..
            } => {
                assert_eq!(workspace_count, 1);
                assert_eq!(analysis_count, 0);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        tx.send(StateMessage::Shutdown).await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn queued_query_after_shutdown_is_drained_and_replied() {
        let (tx, rx) = mpsc::channel(8);
        let state = DaemonState::new(GroveConfig::default(), None);

        let (query_reply_tx, query_reply_rx) = oneshot::channel();

        tx.try_send(StateMessage::Shutdown).unwrap();
        tx.try_send(StateMessage::Query {
            request: QueryRequest::GetStatus,
            reply: query_reply_tx,
        })
        .unwrap();
        drop(tx);

        state.run(rx).await;

        match query_reply_rx.await.unwrap() {
            QueryResponse::Status {
                workspace_count,
                analysis_count,
                base_commit,
            } => {
                assert_eq!(workspace_count, 0);
                assert_eq!(analysis_count, 0);
                assert_eq!(base_commit, "");
            }
            other => panic!("expected status response, got: {other:?}"),
        }
    }
}
