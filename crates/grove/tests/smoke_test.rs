//! End-to-end integration tests exercising the full daemon → CLI client path.
//!
//! Each test spins up an in-process state actor and socket server (no daemonization),
//! registers workspaces directly via the state channel, then queries through the
//! `DaemonClient` — the same client the real CLI uses.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use grove_cli::client::{ClientError, DaemonClient};
use grove_daemon::socket::SocketServer;
use grove_daemon::state::{GroveConfig, StateMessage, spawn_state_actor};
use grove_lib::{
    ChangeType, MergeOrder, OrthogonalityScore, Overlap, Workspace, WorkspaceMetadata,
    WorkspacePairAnalysis,
};
use tokio::sync::{Barrier, broadcast, mpsc, oneshot};
use uuid::Uuid;

// === Test Harness ===

struct TestDaemon {
    _dir: tempfile::TempDir,
    state_tx: mpsc::Sender<StateMessage>,
    state_handle: tokio::task::JoinHandle<()>,
    server_handle: tokio::task::JoinHandle<Result<(), grove_daemon::socket::SocketError>>,
    shutdown_tx: broadcast::Sender<()>,
    client: DaemonClient,
}

impl TestDaemon {
    async fn start() -> Self {
        Self::start_with_config(GroveConfig::default()).await
    }

    async fn start_with_config(config: GroveConfig) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("grove.sock");

        let (state_tx, state_handle) = spawn_state_actor(config, None);
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        let server = SocketServer::new(socket_path.clone(), state_tx.clone());
        let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

        // Wait for socket to be ready
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let client = DaemonClient::new(&socket_path);

        Self {
            _dir: dir,
            state_tx,
            state_handle,
            server_handle,
            shutdown_tx,
            client,
        }
    }

    /// Register a workspace directly via the state actor channel.
    async fn register_workspace(&self, workspace: Workspace) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.state_tx
            .send(StateMessage::RegisterWorkspace {
                workspace,
                reply: reply_tx,
            })
            .await
            .expect("state actor alive");
        reply_rx.await.expect("reply channel open")
    }

    /// Submit a completed analysis directly via the state actor channel.
    async fn submit_analysis(&self, analysis: WorkspacePairAnalysis) {
        self.state_tx
            .send(StateMessage::AnalysisComplete {
                pair: (analysis.workspace_a, analysis.workspace_b),
                result: analysis,
            })
            .await
            .expect("state actor alive");
        // Give the actor a moment to process
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    async fn shutdown(self) {
        drop(self.shutdown_tx);
        let _ = self.state_tx.send(StateMessage::Shutdown).await;
        let _ = self.server_handle.await;
        let _ = self.state_handle.await;
    }
}

fn make_workspace(name: &str, branch: &str) -> Workspace {
    Workspace {
        id: Uuid::new_v4(),
        name: name.to_string(),
        branch: branch.to_string(),
        path: PathBuf::from(format!("/worktrees/{name}")),
        base_ref: "abc1234567890def".to_string(),
        created_at: Utc::now(),
        last_activity: Utc::now(),
        metadata: WorkspaceMetadata::default(),
    }
}

fn unix_socket_bind_supported() -> bool {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("bind-probe.sock");
    match std::os::unix::net::UnixListener::bind(&socket_path) {
        Ok(listener) => {
            drop(listener);
            let _ = std::fs::remove_file(&socket_path);
            true
        }
        Err(_) => false,
    }
}

// === Tests ===

#[tokio::test]
async fn status_returns_correct_counts() {
    let daemon = TestDaemon::start().await;

    // Fresh daemon — zero workspaces, zero analyses
    let resp = daemon.client.status().await.unwrap();
    assert!(resp.ok);
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 0);
    assert_eq!(data["analysis_count"], 0);

    // Register two workspaces
    let ws_a = make_workspace("feature-auth", "feat/auth");
    let ws_b = make_workspace("feature-payments", "feat/payments");
    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 2);
    assert_eq!(data["analysis_count"], 0);

    daemon.shutdown().await;
}

#[tokio::test]
async fn list_workspaces_returns_all_registered() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("ws-alpha", "feat/alpha");
    let ws_b = make_workspace("ws-beta", "feat/beta");
    let ws_c = make_workspace("ws-gamma", "feat/gamma");
    let id_a = ws_a.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();
    daemon.register_workspace(ws_c).await.unwrap();

    let resp = daemon.client.list_workspaces().await.unwrap();
    assert!(resp.ok);

    let workspaces = resp.data.unwrap();
    let workspaces = workspaces.as_array().unwrap();
    assert_eq!(workspaces.len(), 3);

    // Verify structure — each workspace has expected fields
    let names: Vec<&str> = workspaces
        .iter()
        .map(|w| w["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"ws-alpha"));
    assert!(names.contains(&"ws-beta"));
    assert!(names.contains(&"ws-gamma"));

    // Also verify get_workspace for a specific ID
    let resp = daemon
        .client
        .get_workspace(&id_a.to_string())
        .await
        .unwrap();
    assert!(resp.ok);
    let ws_data = resp.data.unwrap();
    assert_eq!(ws_data["name"], "ws-alpha");
    assert_eq!(ws_data["branch"], "feat/alpha");

    daemon.shutdown().await;
}

#[tokio::test]
async fn get_workspace_nonexistent_returns_error() {
    let daemon = TestDaemon::start().await;

    let fake_id = Uuid::new_v4();
    let resp = daemon
        .client
        .get_workspace(&fake_id.to_string())
        .await
        .unwrap();
    assert!(!resp.ok);
    assert!(resp.error.unwrap().contains("not found"));

    daemon.shutdown().await;
}

#[tokio::test]
async fn conflicts_between_overlapping_workspaces() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("feature-auth", "feat/auth");
    let ws_b = make_workspace("feature-user", "feat/user");
    let id_a = ws_a.id;
    let id_b = ws_b.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    // Simulate an analysis result with file and hunk overlaps
    let analysis = WorkspacePairAnalysis {
        workspace_a: id_a,
        workspace_b: id_b,
        score: OrthogonalityScore::Red,
        overlaps: vec![
            Overlap::File {
                path: PathBuf::from("src/auth/handler.ts"),
                a_change: ChangeType::Modified,
                b_change: ChangeType::Modified,
            },
            Overlap::Hunk {
                path: PathBuf::from("src/auth/handler.ts"),
                a_range: grove_lib::LineRange { start: 10, end: 25 },
                b_range: grove_lib::LineRange { start: 20, end: 35 },
                distance: 0,
            },
            Overlap::Symbol {
                path: PathBuf::from("src/auth/handler.ts"),
                symbol_name: "validateToken".to_string(),
                a_modification: "changed return type".to_string(),
                b_modification: "added parameter".to_string(),
            },
        ],
        merge_order_hint: MergeOrder::NeedsCoordination,
        last_computed: Utc::now(),
    };

    daemon.submit_analysis(analysis).await;

    // Query conflicts via the CLI client
    let resp = daemon
        .client
        .conflicts(&id_a.to_string(), &id_b.to_string())
        .await
        .unwrap();
    assert!(resp.ok);

    let data = resp.data.unwrap();
    assert_eq!(data["score"], "Red");
    assert_eq!(data["merge_order_hint"], "NeedsCoordination");

    let overlaps = data["overlaps"].as_array().unwrap();
    assert_eq!(overlaps.len(), 3);

    // Verify overlap types are present
    let overlap_types: Vec<&str> = overlaps
        .iter()
        .filter_map(|o| {
            // Serde tags externally-tagged enums as { "VariantName": { fields } }
            o.as_object()
                .and_then(|m| m.keys().next().map(|s| s.as_str()))
        })
        .collect();
    assert!(overlap_types.contains(&"File"));
    assert!(overlap_types.contains(&"Hunk"));
    assert!(overlap_types.contains(&"Symbol"));

    daemon.shutdown().await;
}

#[tokio::test]
async fn conflicts_no_analysis_returns_error() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("ws-a", "feat/a");
    let ws_b = make_workspace("ws-b", "feat/b");
    let id_a = ws_a.id;
    let id_b = ws_b.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    // No analysis submitted — should get an error
    let resp = daemon
        .client
        .conflicts(&id_a.to_string(), &id_b.to_string())
        .await
        .unwrap();
    assert!(!resp.ok);
    assert!(resp.error.unwrap().contains("not found"));

    daemon.shutdown().await;
}

#[tokio::test]
async fn status_reflects_analysis_count() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("ws-a", "feat/a");
    let ws_b = make_workspace("ws-b", "feat/b");
    let ws_c = make_workspace("ws-c", "feat/c");
    let id_a = ws_a.id;
    let id_b = ws_b.id;
    let id_c = ws_c.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();
    daemon.register_workspace(ws_c).await.unwrap();

    // Submit two analyses
    let analysis_ab = WorkspacePairAnalysis {
        workspace_a: id_a,
        workspace_b: id_b,
        score: OrthogonalityScore::Green,
        overlaps: vec![],
        merge_order_hint: MergeOrder::Either,
        last_computed: Utc::now(),
    };
    let analysis_bc = WorkspacePairAnalysis {
        workspace_a: id_b,
        workspace_b: id_c,
        score: OrthogonalityScore::Yellow,
        overlaps: vec![Overlap::File {
            path: PathBuf::from("shared.ts"),
            a_change: ChangeType::Modified,
            b_change: ChangeType::Added,
        }],
        merge_order_hint: MergeOrder::BFirst,
        last_computed: Utc::now(),
    };

    daemon.submit_analysis(analysis_ab).await;
    daemon.submit_analysis(analysis_bc).await;

    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 3);
    assert_eq!(data["analysis_count"], 2);

    daemon.shutdown().await;
}

#[tokio::test]
async fn get_all_analyses_returns_submitted_results() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("ws-a", "feat/a");
    let ws_b = make_workspace("ws-b", "feat/b");
    let id_a = ws_a.id;
    let id_b = ws_b.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    let analysis = WorkspacePairAnalysis {
        workspace_a: id_a,
        workspace_b: id_b,
        score: OrthogonalityScore::Yellow,
        overlaps: vec![Overlap::File {
            path: PathBuf::from("package.json"),
            a_change: ChangeType::Modified,
            b_change: ChangeType::Modified,
        }],
        merge_order_hint: MergeOrder::AFirst,
        last_computed: Utc::now(),
    };

    daemon.submit_analysis(analysis).await;

    let resp = daemon.client.get_all_analyses().await.unwrap();
    assert!(resp.ok);

    let analyses = resp.data.unwrap();
    let analyses = analyses.as_array().unwrap();
    assert_eq!(analyses.len(), 1);
    assert_eq!(analyses[0]["score"], "Yellow");
    assert_eq!(analyses[0]["merge_order_hint"], "AFirst");

    daemon.shutdown().await;
}

#[tokio::test]
async fn multiple_clients_concurrent_access() {
    let daemon = TestDaemon::start().await;

    // Register some workspaces
    for i in 0..5 {
        let ws = make_workspace(&format!("ws-{i}"), &format!("feat/{i}"));
        daemon.register_workspace(ws).await.unwrap();
    }

    // Spawn multiple concurrent client requests
    let mut handles = Vec::new();
    let socket_path = daemon.client.socket_path().to_path_buf();

    for _ in 0..10 {
        let path = socket_path.clone();
        handles.push(tokio::spawn(async move {
            let client = DaemonClient::new(&path);
            let resp = client.status().await.unwrap();
            assert!(resp.ok);
            let data = resp.data.unwrap();
            assert_eq!(data["workspace_count"], 5);
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    daemon.shutdown().await;
}

#[tokio::test]
async fn unknown_method_returns_error() {
    let daemon = TestDaemon::start().await;

    let resp = daemon
        .client
        .request("nonexistent_method", serde_json::json!({}))
        .await
        .unwrap();
    assert!(!resp.ok);
    assert!(resp.error.unwrap().contains("unknown method"));

    daemon.shutdown().await;
}

#[tokio::test]
async fn workspace_registration_enforces_max_limit() {
    let config = GroveConfig {
        max_worktrees: 2,
        ..GroveConfig::default()
    };
    let daemon = TestDaemon::start_with_config(config).await;

    let ws_a = make_workspace("ws-a", "feat/a");
    let ws_b = make_workspace("ws-b", "feat/b");
    let ws_c = make_workspace("ws-c", "feat/c");

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    // Third should fail
    let result = daemon.register_workspace(ws_c).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("maximum"));

    // Status should still show 2
    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 2);

    daemon.shutdown().await;
}

#[tokio::test]
async fn remove_workspace_clears_associated_analyses() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("ws-a", "feat/a");
    let ws_b = make_workspace("ws-b", "feat/b");
    let ws_c = make_workspace("ws-c", "feat/c");
    let id_a = ws_a.id;
    let id_b = ws_b.id;
    let id_c = ws_c.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();
    daemon.register_workspace(ws_c).await.unwrap();

    // Submit analysis between A-B and B-C
    daemon
        .submit_analysis(WorkspacePairAnalysis {
            workspace_a: id_a,
            workspace_b: id_b,
            score: OrthogonalityScore::Green,
            overlaps: vec![],
            merge_order_hint: MergeOrder::Either,
            last_computed: Utc::now(),
        })
        .await;

    daemon
        .submit_analysis(WorkspacePairAnalysis {
            workspace_a: id_b,
            workspace_b: id_c,
            score: OrthogonalityScore::Yellow,
            overlaps: vec![],
            merge_order_hint: MergeOrder::Either,
            last_computed: Utc::now(),
        })
        .await;

    // Verify 2 analyses
    let resp = daemon.client.status().await.unwrap();
    assert_eq!(resp.data.unwrap()["analysis_count"], 2);

    // Remove workspace B — should clear both analyses involving B
    let (reply_tx, reply_rx) = oneshot::channel();
    daemon
        .state_tx
        .send(StateMessage::RemoveWorkspace {
            workspace_id: id_b,
            reply: reply_tx,
        })
        .await
        .unwrap();
    reply_rx.await.unwrap().unwrap();

    // Give actor a moment to process
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 2);
    assert_eq!(data["analysis_count"], 0);

    // The remaining workspaces should be A and C
    let resp = daemon.client.list_workspaces().await.unwrap();
    let workspaces = resp.data.unwrap();
    let names: Vec<&str> = workspaces
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"ws-a"));
    assert!(names.contains(&"ws-c"));
    assert!(!names.contains(&"ws-b"));

    daemon.shutdown().await;
}

#[tokio::test]
async fn base_ref_change_clears_analyses() {
    let daemon = TestDaemon::start().await;

    let ws_a = make_workspace("ws-a", "feat/a");
    let ws_b = make_workspace("ws-b", "feat/b");
    let id_a = ws_a.id;
    let id_b = ws_b.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    daemon
        .submit_analysis(WorkspacePairAnalysis {
            workspace_a: id_a,
            workspace_b: id_b,
            score: OrthogonalityScore::Green,
            overlaps: vec![],
            merge_order_hint: MergeOrder::Either,
            last_computed: Utc::now(),
        })
        .await;

    // Verify analysis exists
    let resp = daemon.client.status().await.unwrap();
    assert_eq!(resp.data.unwrap()["analysis_count"], 1);

    // Simulate base ref change
    daemon
        .state_tx
        .send(StateMessage::BaseRefChanged {
            new_commit: "newcommithash123".to_string(),
        })
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Analyses should be cleared, base commit updated
    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["analysis_count"], 0);
    assert_eq!(data["base_commit"], "newcommithash123");

    daemon.shutdown().await;
}

#[tokio::test]
async fn full_workflow_register_analyze_query_remove() {
    let daemon = TestDaemon::start().await;

    // 1. Start with empty state
    let resp = daemon.client.status().await.unwrap();
    assert_eq!(resp.data.unwrap()["workspace_count"], 0);

    // 2. Register workspaces
    let ws_a = make_workspace("feature-auth", "feat/auth");
    let ws_b = make_workspace("feature-payments", "feat/payments");
    let id_a = ws_a.id;
    let id_b = ws_b.id;

    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    // 3. Submit analysis with overlaps
    let analysis = WorkspacePairAnalysis {
        workspace_a: id_a,
        workspace_b: id_b,
        score: OrthogonalityScore::Black,
        overlaps: vec![
            Overlap::File {
                path: PathBuf::from("src/shared/types.ts"),
                a_change: ChangeType::Modified,
                b_change: ChangeType::Deleted,
            },
            Overlap::Dependency {
                changed_in: id_a,
                changed_file: PathBuf::from("src/auth/service.ts"),
                changed_export: grove_lib::ExportDelta::Removed(grove_lib::Symbol {
                    name: "AuthService".to_string(),
                    kind: grove_lib::SymbolKind::Class,
                    range: grove_lib::LineRange { start: 1, end: 50 },
                    signature: None,
                }),
                affected_file: PathBuf::from("src/payments/checkout.ts"),
                affected_usage: vec![grove_lib::Location {
                    file: PathBuf::from("src/payments/checkout.ts"),
                    line: 3,
                    column: 10,
                }],
            },
        ],
        merge_order_hint: MergeOrder::AFirst,
        last_computed: Utc::now(),
    };

    daemon.submit_analysis(analysis).await;

    // 4. Query via client
    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 2);
    assert_eq!(data["analysis_count"], 1);

    let resp = daemon
        .client
        .conflicts(&id_a.to_string(), &id_b.to_string())
        .await
        .unwrap();
    assert!(resp.ok);
    let data = resp.data.unwrap();
    assert_eq!(data["score"], "Black");
    assert_eq!(data["overlaps"].as_array().unwrap().len(), 2);

    // 5. Remove workspace A (simulating merge/retire)
    let (reply_tx, reply_rx) = oneshot::channel();
    daemon
        .state_tx
        .send(StateMessage::RemoveWorkspace {
            workspace_id: id_a,
            reply: reply_tx,
        })
        .await
        .unwrap();
    reply_rx.await.unwrap().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // 6. Verify cleanup
    let resp = daemon.client.status().await.unwrap();
    let data = resp.data.unwrap();
    assert_eq!(data["workspace_count"], 1);
    assert_eq!(data["analysis_count"], 0);

    let resp = daemon
        .client
        .get_workspace(&id_a.to_string())
        .await
        .unwrap();
    assert!(!resp.ok); // removed

    let resp = daemon
        .client
        .get_workspace(&id_b.to_string())
        .await
        .unwrap();
    assert!(resp.ok); // still exists

    daemon.shutdown().await;
}

#[tokio::test]
async fn startup_readiness_retry_loop_eventually_reaches_daemon() {
    if !unix_socket_bind_supported() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("grove.sock");

    let (state_tx, state_handle) = spawn_state_actor(GroveConfig::default(), None);
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let server = SocketServer::new(socket_path.clone(), state_tx.clone());
    let server_handle = tokio::spawn(async move { server.run(shutdown_rx).await });

    // Simulate caller-side startup retries while the socket is still coming up.
    let client = DaemonClient::new(&socket_path);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut reached_daemon = false;
    while tokio::time::Instant::now() < deadline {
        match client.status().await {
            Ok(response) => {
                assert!(response.ok);
                reached_daemon = true;
                break;
            }
            Err(ClientError::DaemonNotRunning(_) | ClientError::Connection(_)) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(other) => panic!("unexpected startup error during retry loop: {other}"),
        }
    }
    assert!(
        reached_daemon,
        "daemon never became reachable before deadline"
    );

    drop(shutdown_tx);
    state_tx.send(StateMessage::Shutdown).await.unwrap();
    let _ = server_handle.await;
    state_handle.await.unwrap();
}

#[tokio::test]
async fn shutdown_removes_socket_and_subsequent_requests_fail_fast() {
    if !unix_socket_bind_supported() {
        return;
    }

    let daemon = TestDaemon::start().await;
    let socket_path = daemon.client.socket_path().to_path_buf();

    let warmup = daemon.client.status().await.unwrap();
    assert!(warmup.ok);

    daemon.shutdown().await;

    for _ in 0..100 {
        if !socket_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !socket_path.exists(),
        "socket path should be removed on shutdown: {}",
        socket_path.display()
    );

    let client = DaemonClient::new(&socket_path);
    match client.status().await {
        Err(ClientError::DaemonNotRunning(path)) => assert_eq!(path, socket_path),
        Err(other) => panic!("unexpected post-shutdown client error: {other}"),
        Ok(response) => panic!("expected failure after shutdown, got: {response:?}"),
    }
}

#[tokio::test]
async fn in_flight_status_requests_during_shutdown_do_not_hang() {
    if !unix_socket_bind_supported() {
        return;
    }

    let daemon = TestDaemon::start().await;
    let socket_path = daemon.client.socket_path().to_path_buf();

    let barrier = Arc::new(Barrier::new(17));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let path = socket_path.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let client = DaemonClient::new(&path);
            barrier.wait().await;
            tokio::time::timeout(Duration::from_secs(1), client.status()).await
        }));
    }

    barrier.wait().await;
    daemon.shutdown().await;

    for task in tasks {
        match task.await.unwrap() {
            Ok(Ok(response)) => {
                if response.ok {
                    continue;
                }
                let error = response
                    .error
                    .as_deref()
                    .expect("structured error response should include `error`");
                assert!(
                    !error.trim().is_empty(),
                    "structured error response should include non-empty `error`"
                );
            }
            Ok(Err(
                ClientError::DaemonNotRunning(_)
                | ClientError::Connection(_)
                | ClientError::Protocol(_),
            )) => {}
            Ok(Err(other)) => panic!("unexpected client error during shutdown race: {other}"),
            Err(_) => panic!("status request timed out during shutdown race"),
        }
    }
}

#[tokio::test]
async fn sync_worktrees_registers_and_removes_via_socket() {
    let daemon = TestDaemon::start().await;

    // Register two workspaces manually first (these use UUID v4)
    let ws_a = make_workspace("ws-alpha", "feat/alpha");
    let ws_b = make_workspace("ws-beta", "feat/beta");
    daemon.register_workspace(ws_a).await.unwrap();
    daemon.register_workspace(ws_b).await.unwrap();

    // Verify 2 workspaces registered
    let resp = daemon.client.status().await.unwrap();
    assert_eq!(resp.data.unwrap()["workspace_count"], 2);

    // Sync with alpha + a new gamma.
    // sync_worktrees derives IDs via UUID v5 from path, so the v5 IDs won't match
    // the v4 IDs we registered above. The sync will treat all manually-registered
    // workspaces as stale and remove them, then add both alpha and gamma with v5 IDs.
    let resp = daemon
        .client
        .sync_worktrees(serde_json::json!([
            {"name": "ws-alpha", "path": "/worktrees/ws-alpha", "branch": "refs/heads/feat/alpha", "head": "abc123"},
            {"name": "ws-gamma", "path": "/worktrees/ws-gamma", "branch": "refs/heads/feat/gamma", "head": "def456"},
        ]))
        .await
        .unwrap();

    assert!(resp.ok, "sync_worktrees should succeed: {:?}", resp.error);
    let data = resp.data.unwrap();

    // The v5 IDs won't match the v4 IDs, so all 2 originals are removed and both
    // desired workspaces (alpha + gamma) are added as new.
    let added = data["added"].as_array().unwrap();
    let removed = data["removed"].as_array().unwrap();
    assert_eq!(added.len(), 2, "should add 2 workspaces (alpha+gamma with v5 IDs)");
    assert_eq!(removed.len(), 2, "should remove 2 workspaces (original v4 IDs)");

    // Verify final state: 2 workspaces (alpha + gamma)
    let resp = daemon.client.status().await.unwrap();
    assert_eq!(resp.data.unwrap()["workspace_count"], 2);

    // Verify the workspace names are present
    let resp = daemon.client.list_workspaces().await.unwrap();
    let workspaces = resp.data.unwrap();
    let names: Vec<&str> = workspaces
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["name"].as_str())
        .collect();
    assert!(names.contains(&"ws-alpha") || names.iter().any(|n| n.contains("alpha")));

    daemon.shutdown().await;
}
