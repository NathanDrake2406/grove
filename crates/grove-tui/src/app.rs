use crossterm::event::{KeyCode, KeyEvent};
use grove_cli::client::DaemonClient;
use grove_lib::{OrthogonalityScore, Workspace, WorkspacePairAnalysis};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPanel {
    Worktrees,
    Pairs,
}

#[derive(Debug)]
pub enum ViewState {
    Loading,
    NoWorktrees,
    Dashboard,
    Error(String),
}

// Implement partial eq manually for view state comparisons
impl PartialEq for ViewState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Loading, Self::Loading) => true,
            (Self::NoWorktrees, Self::NoWorktrees) => true,
            (Self::Dashboard, Self::Dashboard) => true,
            (Self::Error(a), Self::Error(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for ViewState {}

pub struct App {
    pub client: DaemonClient,
    pub is_dirty: bool,
    pub view_state: ViewState,

    // Data models
    pub workspaces: Vec<Workspace>,
    pub analyses: Vec<WorkspacePairAnalysis>,
    pub base_commit: String,

    // Dashboard selection state
    pub selected_worktree_index: usize,
    pub selected_pair_index: usize,

    // Dual-panel focus
    pub focused_panel: FocusedPanel,

    /// When the data last changed (for the "updated Xs ago" indicator).
    pub last_data_change: Instant,
}

impl App {
    pub fn new(client: DaemonClient) -> Self {
        Self {
            client,
            is_dirty: true,
            view_state: ViewState::Loading,
            workspaces: Vec::new(),
            analyses: Vec::new(),
            base_commit: String::new(),
            selected_worktree_index: 0,
            selected_pair_index: 0,
            focused_panel: FocusedPanel::Worktrees,
            last_data_change: Instant::now(),
        }
    }

    /// Fetches the latest data from the daemon.
    pub async fn refresh_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Fetch status for base_commit
        let status_resp = self.client.status().await?;
        if let Some(commit) = status_resp
            .ok
            .then_some(status_resp.data.as_ref())
            .flatten()
            .and_then(|d| d.get("base_commit"))
            .and_then(|v| v.as_str())
        {
            let short = if commit.len() > 8 {
                &commit[..8]
            } else {
                commit
            };
            self.base_commit = short.to_string();
        }

        // Fetch workspaces
        let ws_resp = self.client.list_workspaces().await?;
        if !ws_resp.ok {
            self.set_error(
                ws_resp
                    .error
                    .unwrap_or_else(|| "Failed to list workspaces".to_string()),
            );
            return Ok(());
        }

        let new_workspaces: Vec<Workspace> =
            serde_json::from_value(ws_resp.data.unwrap_or_default())?;

        // Fetch analyses
        let an_resp = self.client.get_all_analyses().await?;
        if !an_resp.ok {
            self.set_error(
                an_resp
                    .error
                    .unwrap_or_else(|| "Failed to get analyses".to_string()),
            );
            return Ok(());
        }

        let new_analyses: Vec<WorkspacePairAnalysis> =
            serde_json::from_value(an_resp.data.unwrap_or_default())?;

        let changed = self.workspaces.len() != new_workspaces.len()
            || self.analyses.len() != new_analyses.len()
            || !self.analyses_are_equal(&self.analyses, &new_analyses);

        if changed || self.view_state == ViewState::Loading {
            let previous_selected_workspace_id = self
                .workspaces
                .get(self.selected_worktree_index)
                .map(|w| w.id);
            let previous_selected_worktree_index = self.selected_worktree_index;
            let previous_selected_pair_index = self.selected_pair_index;

            self.analyses = new_analyses;
            self.last_data_change = Instant::now();
            self.is_dirty = true;

            // Sort worktrees: conflicting first, clean last
            let mut sorted = new_workspaces;
            sorted.sort_by_key(|w| {
                let has_conflicts = self.analyses.iter().any(|a| {
                    (a.workspace_a == w.id || a.workspace_b == w.id)
                        && a.score != OrthogonalityScore::Green
                });
                // false (has conflicts) sorts before true (clean)
                !has_conflicts
            });
            self.workspaces = sorted;

            self.selected_worktree_index = if self.workspaces.is_empty() {
                0
            } else if let Some(selected_id) = previous_selected_workspace_id {
                self.workspaces
                    .iter()
                    .position(|w| w.id == selected_id)
                    .unwrap_or_else(|| {
                        previous_selected_worktree_index.min(self.workspaces.len() - 1)
                    })
            } else {
                0
            };

            self.selected_pair_index =
                if let Some(ws) = self.workspaces.get(self.selected_worktree_index) {
                    let pair_count = self.get_pairs_for_worktree(&ws.id).len();
                    if pair_count == 0 {
                        0
                    } else {
                        previous_selected_pair_index.min(pair_count - 1)
                    }
                } else {
                    0
                };

            // Automatically transition state
            if self.view_state == ViewState::Loading || self.view_state == ViewState::NoWorktrees {
                if self.workspaces.len() <= 1 {
                    self.view_state = ViewState::NoWorktrees;
                } else {
                    self.view_state = ViewState::Dashboard;
                }
            }
        }

        Ok(())
    }

    fn analyses_are_equal(
        &self,
        old: &[WorkspacePairAnalysis],
        new: &[WorkspacePairAnalysis],
    ) -> bool {
        if old.len() != new.len() {
            return false;
        }
        for (a, b) in old.iter().zip(new.iter()) {
            if a.last_computed != b.last_computed {
                return false;
            }
        }
        true
    }

    pub fn set_error(&mut self, err: String) {
        if self.view_state != ViewState::Error(err.clone()) {
            self.view_state = ViewState::Error(err);
            self.is_dirty = true;
        }
    }

    /// Compute summary statistics for the header bar.
    /// Returns (worktree_count, base_commit_short, conflict_count, clean_count).
    pub fn summary_stats(&self) -> (usize, &str, usize, usize) {
        let worktree_count = self.workspaces.len();
        let base = if self.base_commit.is_empty() {
            "(none)"
        } else {
            self.base_commit.as_str()
        };

        let conflict_count = self
            .analyses
            .iter()
            .filter(|a| a.score != OrthogonalityScore::Green)
            .count();

        // Count worktrees that have at least one conflict pair
        let conflict_ws_count = self
            .workspaces
            .iter()
            .filter(|w| !self.get_pairs_for_worktree(&w.id).is_empty())
            .count();
        let clean_count = worktree_count.saturating_sub(conflict_ws_count);

        (worktree_count, base, conflict_count, clean_count)
    }

    /// Human-friendly label for how long ago data last changed.
    pub fn last_updated_label(&self) -> String {
        let elapsed = self.last_data_change.elapsed().as_secs();
        if elapsed < 5 {
            "just now".to_string()
        } else if elapsed < 120 {
            "< 2m ago".to_string()
        } else {
            format!("{}m ago", elapsed / 60)
        }
    }

    pub fn handle_input(&mut self, key: KeyEvent) -> bool {
        // Return true if we should exit
        match self.view_state {
            ViewState::Dashboard => self.handle_dashboard_input(key),
            ViewState::Loading | ViewState::NoWorktrees | ViewState::Error(_) => {
                matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
            }
        }
    }

    fn handle_dashboard_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,

            KeyCode::Left | KeyCode::Char('h') => {
                self.focused_panel = FocusedPanel::Worktrees;
                self.is_dirty = true;
            }

            KeyCode::Right | KeyCode::Char('l') | KeyCode::Tab => {
                self.focused_panel = FocusedPanel::Pairs;
                self.is_dirty = true;
            }

            KeyCode::Char('r') => {
                // Force refresh — mark dirty to re-draw; the tick will re-fetch data
                self.is_dirty = true;
            }

            KeyCode::Char('j') | KeyCode::Down => match self.focused_panel {
                FocusedPanel::Worktrees => {
                    if !self.workspaces.is_empty() {
                        self.selected_worktree_index =
                            (self.selected_worktree_index + 1).min(self.workspaces.len() - 1);
                        self.selected_pair_index = 0;
                        self.is_dirty = true;
                    }
                }
                FocusedPanel::Pairs => {
                    if let Some(ws) = self.workspaces.get(self.selected_worktree_index) {
                        let pair_count = self.get_pairs_for_worktree(&ws.id).len();
                        if pair_count > 0 {
                            self.selected_pair_index =
                                (self.selected_pair_index + 1).min(pair_count - 1);
                            self.is_dirty = true;
                        }
                    }
                }
            },

            KeyCode::Char('k') | KeyCode::Up => match self.focused_panel {
                FocusedPanel::Worktrees => {
                    if self.selected_worktree_index > 0 {
                        self.selected_worktree_index -= 1;
                        self.selected_pair_index = 0;
                        self.is_dirty = true;
                    }
                }
                FocusedPanel::Pairs => {
                    if self.selected_pair_index > 0 {
                        self.selected_pair_index -= 1;
                        self.is_dirty = true;
                    }
                }
            },

            _ => {}
        }
        false
    }

    /// Gets all analyses where the given workspace ID is either workspace_a or workspace_b.
    /// Filters out pairs that have a Green score (no conflicts).
    pub fn get_pairs_for_worktree(
        &self,
        id: &grove_lib::WorkspaceId,
    ) -> Vec<&WorkspacePairAnalysis> {
        self.analyses
            .iter()
            .filter(|a| {
                (a.workspace_a == *id || a.workspace_b == *id)
                    && a.score != OrthogonalityScore::Green
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyCode;
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn make_workspace(id: &str, name: &str, branch: &str, path: &str) -> Workspace {
        serde_json::from_value(json!({
            "id": id,
            "name": name,
            "branch": branch,
            "path": path,
            "base_ref": "refs/heads/main",
            "created_at": "2026-01-01T00:00:00Z",
            "last_activity": "2026-01-01T00:00:00Z",
            "metadata": {}
        }))
        .unwrap()
    }

    fn make_analysis(
        a: &str,
        b: &str,
        score: &str,
        last_computed: &str,
        overlaps: Vec<serde_json::Value>,
    ) -> WorkspacePairAnalysis {
        serde_json::from_value(json!({
            "workspace_a": a,
            "workspace_b": b,
            "score": score,
            "overlaps": overlaps,
            "merge_order_hint": "Either",
            "last_computed": last_computed
        }))
        .unwrap()
    }

    fn fake_client() -> DaemonClient {
        DaemonClient::new("/tmp/nonexistent-grove-tui-tests.sock")
    }

    fn spawn_mock_daemon(
        socket_path: PathBuf,
        responses: Vec<serde_json::Value>,
    ) -> tokio::task::JoinHandle<()> {
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).unwrap();

        tokio::spawn(async move {
            for response in responses {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                let bytes = reader.read_line(&mut line).await.unwrap();
                assert!(bytes > 0, "expected request line from client");

                let mut stream = reader.into_inner();
                stream
                    .write_all(response.to_string().as_bytes())
                    .await
                    .unwrap();
                stream.write_all(b"\n").await.unwrap();
            }
        })
    }

    #[test]
    fn view_state_partial_eq_handles_error_payloads() {
        assert_eq!(ViewState::Loading, ViewState::Loading);
        assert_eq!(ViewState::NoWorktrees, ViewState::NoWorktrees);
        assert_eq!(ViewState::Dashboard, ViewState::Dashboard);
        assert_eq!(
            ViewState::Error("boom".to_string()),
            ViewState::Error("boom".to_string())
        );
        assert_ne!(
            ViewState::Error("boom".to_string()),
            ViewState::Error("other".to_string())
        );
    }

    #[test]
    fn summary_stats_and_pair_filtering_ignore_green_pairs() {
        let ws_a = make_workspace(
            "00000000-0000-0000-0000-000000000001",
            "conflict-a",
            "feature/a",
            "/tmp/a",
        );
        let ws_b = make_workspace(
            "00000000-0000-0000-0000-000000000002",
            "conflict-b",
            "feature/b",
            "/tmp/b",
        );
        let ws_c = make_workspace(
            "00000000-0000-0000-0000-000000000003",
            "clean-c",
            "feature/c",
            "/tmp/c",
        );

        let mut app = App::new(fake_client());
        app.workspaces = vec![ws_a.clone(), ws_b, ws_c];
        app.base_commit = "12345678".to_string();
        app.analyses = vec![
            make_analysis(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
                "Yellow",
                "2026-01-01T00:00:00Z",
                vec![json!({
                    "File": {
                        "path": "src/lib.rs",
                        "a_change": "Modified",
                        "b_change": "Modified"
                    }
                })],
            ),
            make_analysis(
                "00000000-0000-0000-0000-000000000002",
                "00000000-0000-0000-0000-000000000003",
                "Green",
                "2026-01-01T00:00:00Z",
                vec![],
            ),
        ];

        let (worktree_count, base, conflict_count, clean_count) = app.summary_stats();
        assert_eq!(worktree_count, 3);
        assert_eq!(base, "12345678");
        assert_eq!(conflict_count, 1);
        assert_eq!(clean_count, 1);

        let pairs_for_a = app.get_pairs_for_worktree(&ws_a.id);
        assert_eq!(pairs_for_a.len(), 1);
        assert_eq!(pairs_for_a[0].score, OrthogonalityScore::Yellow);
    }

    #[test]
    fn last_updated_label_has_expected_buckets() {
        let mut app = App::new(fake_client());

        app.last_data_change = Instant::now() - Duration::from_secs(2);
        assert_eq!(app.last_updated_label(), "just now");

        app.last_data_change = Instant::now() - Duration::from_secs(60);
        assert_eq!(app.last_updated_label(), "< 2m ago");

        app.last_data_change = Instant::now() - Duration::from_secs(180);
        assert_eq!(app.last_updated_label(), "3m ago");
    }

    #[test]
    fn handle_input_non_dashboard_only_exits_on_quit_keys() {
        let mut app = App::new(fake_client());
        app.view_state = ViewState::Loading;

        assert!(app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Char('q'))));
        assert!(app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Esc)));
        assert!(!app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Char('x'))));
    }

    #[test]
    fn dashboard_navigation_updates_focus_and_selection() {
        let ws_a = make_workspace(
            "00000000-0000-0000-0000-000000000001",
            "alpha",
            "feature/a",
            "/tmp/a",
        );
        let ws_b = make_workspace(
            "00000000-0000-0000-0000-000000000002",
            "beta",
            "feature/b",
            "/tmp/b",
        );
        let ws_c = make_workspace(
            "00000000-0000-0000-0000-000000000003",
            "gamma",
            "feature/c",
            "/tmp/c",
        );

        let mut app = App::new(fake_client());
        app.view_state = ViewState::Dashboard;
        app.workspaces = vec![ws_a, ws_b, ws_c];
        app.analyses = vec![
            make_analysis(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
                "Yellow",
                "2026-01-01T00:00:00Z",
                vec![json!({
                    "File": {
                        "path": "src/a.rs",
                        "a_change": "Modified",
                        "b_change": "Modified"
                    }
                })],
            ),
            make_analysis(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000003",
                "Red",
                "2026-01-01T00:01:00Z",
                vec![json!({
                    "Symbol": {
                        "path": "src/a.rs",
                        "symbol_name": "handle",
                        "a_modification": "A",
                        "b_modification": "B"
                    }
                })],
            ),
        ];

        assert_eq!(app.focused_panel, FocusedPanel::Worktrees);
        assert_eq!(app.selected_worktree_index, 0);
        assert_eq!(app.selected_pair_index, 0);

        app.is_dirty = false;
        assert!(!app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Right)));
        assert_eq!(app.focused_panel, FocusedPanel::Pairs);
        assert!(app.is_dirty);

        app.is_dirty = false;
        assert!(!app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Down)));
        assert_eq!(app.selected_pair_index, 1);
        assert!(app.is_dirty);

        app.is_dirty = false;
        assert!(!app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Up)));
        assert_eq!(app.selected_pair_index, 0);
        assert!(app.is_dirty);

        assert!(!app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Left)));
        assert_eq!(app.focused_panel, FocusedPanel::Worktrees);

        assert!(!app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Down)));
        assert_eq!(app.selected_worktree_index, 1);

        assert!(app.handle_input(crossterm::event::KeyEvent::from(KeyCode::Char('q'))));
    }

    #[tokio::test]
    async fn refresh_data_populates_dashboard_and_sorts_conflicted_first() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");

        let responses = vec![
            json!({"ok": true, "data": {"base_commit": "1234567890abcdef"}}),
            json!({
                "ok": true,
                "data": [
                    {
                        "id": "00000000-0000-0000-0000-000000000003",
                        "name": "clean-c",
                        "branch": "feature/c",
                        "path": "/tmp/c",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "name": "conflict-a",
                        "branch": "feature/a",
                        "path": "/tmp/a",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000002",
                        "name": "conflict-b",
                        "branch": "feature/b",
                        "path": "/tmp/b",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    }
                ]
            }),
            json!({
                "ok": true,
                "data": [
                    {
                        "workspace_a": "00000000-0000-0000-0000-000000000001",
                        "workspace_b": "00000000-0000-0000-0000-000000000002",
                        "score": "Yellow",
                        "overlaps": [{
                            "File": {
                                "path": "src/lib.rs",
                                "a_change": "Modified",
                                "b_change": "Modified"
                            }
                        }],
                        "merge_order_hint": "Either",
                        "last_computed": "2026-01-01T00:00:00Z"
                    }
                ]
            }),
        ];

        let server = spawn_mock_daemon(socket_path.clone(), responses);

        let client = DaemonClient::new(&socket_path);
        let mut app = App::new(client);

        app.refresh_data().await.unwrap();

        assert_eq!(app.base_commit, "12345678");
        assert_eq!(app.view_state, ViewState::Dashboard);
        assert_eq!(app.selected_worktree_index, 0);
        assert_eq!(app.selected_pair_index, 0);
        assert_eq!(app.workspaces.len(), 3);
        assert_eq!(app.workspaces[2].name, "clean-c");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_data_sets_error_when_analysis_request_fails() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");

        let responses = vec![
            json!({"ok": true, "data": {"base_commit": "12345678"}}),
            json!({
                "ok": true,
                "data": [
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "name": "alpha",
                        "branch": "feature/a",
                        "path": "/tmp/a",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000002",
                        "name": "beta",
                        "branch": "feature/b",
                        "path": "/tmp/b",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    }
                ]
            }),
            json!({"ok": false, "error": null}),
        ];

        let server = spawn_mock_daemon(socket_path.clone(), responses);

        let client = DaemonClient::new(&socket_path);
        let mut app = App::new(client);

        app.refresh_data().await.unwrap();

        assert_eq!(
            app.view_state,
            ViewState::Error("Failed to get analyses".to_string())
        );
        assert!(app.is_dirty);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_data_sets_error_when_workspace_list_fails() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");

        let responses = vec![
            json!({"ok": true, "data": {"base_commit": "12345678"}}),
            json!({"ok": false, "error": "list failed"}),
        ];

        let server = spawn_mock_daemon(socket_path.clone(), responses);

        let client = DaemonClient::new(&socket_path);
        let mut app = App::new(client);

        app.refresh_data().await.unwrap();

        assert_eq!(app.view_state, ViewState::Error("list failed".to_string()));
        assert!(app.is_dirty);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn refresh_data_preserves_selected_worktree_across_updates() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("daemon.sock");

        let responses = vec![
            json!({"ok": true, "data": {"base_commit": "1234567890abcdef"}}),
            json!({
                "ok": true,
                "data": [
                    {
                        "id": "00000000-0000-0000-0000-000000000003",
                        "name": "clean-c",
                        "branch": "feature/c",
                        "path": "/tmp/c",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "name": "conflict-a",
                        "branch": "feature/a",
                        "path": "/tmp/a",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000002",
                        "name": "conflict-b",
                        "branch": "feature/b",
                        "path": "/tmp/b",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    }
                ]
            }),
            json!({
                "ok": true,
                "data": [
                    {
                        "workspace_a": "00000000-0000-0000-0000-000000000001",
                        "workspace_b": "00000000-0000-0000-0000-000000000002",
                        "score": "Yellow",
                        "overlaps": [{
                            "File": {
                                "path": "src/lib.rs",
                                "a_change": "Modified",
                                "b_change": "Modified"
                            }
                        }],
                        "merge_order_hint": "Either",
                        "last_computed": "2026-01-01T00:00:00Z"
                    }
                ]
            }),
            json!({"ok": true, "data": {"base_commit": "1234567890abcdef"}}),
            json!({
                "ok": true,
                "data": [
                    {
                        "id": "00000000-0000-0000-0000-000000000003",
                        "name": "clean-c",
                        "branch": "feature/c",
                        "path": "/tmp/c",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "name": "conflict-a",
                        "branch": "feature/a",
                        "path": "/tmp/a",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    },
                    {
                        "id": "00000000-0000-0000-0000-000000000002",
                        "name": "conflict-b",
                        "branch": "feature/b",
                        "path": "/tmp/b",
                        "base_ref": "refs/heads/main",
                        "created_at": "2026-01-01T00:00:00Z",
                        "last_activity": "2026-01-01T00:00:00Z",
                        "metadata": {}
                    }
                ]
            }),
            json!({
                "ok": true,
                "data": [
                    {
                        "workspace_a": "00000000-0000-0000-0000-000000000001",
                        "workspace_b": "00000000-0000-0000-0000-000000000002",
                        "score": "Yellow",
                        "overlaps": [{
                            "File": {
                                "path": "src/lib.rs",
                                "a_change": "Modified",
                                "b_change": "Modified"
                            }
                        }],
                        "merge_order_hint": "Either",
                        "last_computed": "2026-01-01T00:00:01Z"
                    }
                ]
            }),
        ];

        let server = spawn_mock_daemon(socket_path.clone(), responses);
        let client = DaemonClient::new(&socket_path);
        let mut app = App::new(client);

        app.refresh_data().await.unwrap();
        assert_eq!(app.workspaces[2].name, "clean-c");
        app.selected_worktree_index = 2;

        app.refresh_data().await.unwrap();

        assert_eq!(app.selected_worktree_index, 2);
        assert_eq!(app.workspaces[app.selected_worktree_index].name, "clean-c");

        server.await.unwrap();
    }

    #[test]
    fn analyses_are_equal_checks_last_computed_only() {
        let app = App::new(fake_client());
        let old = vec![make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Yellow",
            "2026-01-01T00:00:00Z",
            vec![],
        )];
        let same = vec![make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Red",
            "2026-01-01T00:00:00Z",
            vec![],
        )];
        let changed = vec![make_analysis(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "Yellow",
            "2026-01-01T00:00:01Z",
            vec![],
        )];

        assert!(app.analyses_are_equal(&old, &same));
        assert!(!app.analyses_are_equal(&old, &changed));
    }
}
