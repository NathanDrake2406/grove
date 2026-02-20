use crossterm::event::{KeyCode, KeyEvent};
use grove_cli::client::DaemonClient;
use grove_lib::{OrthogonalityScore, Workspace, WorkspacePairAnalysis};

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
        }
    }

    /// Fetches the latest data from the daemon.
    pub async fn refresh_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Fetch status for base_commit
        let status_resp = self.client.status().await?;
        if let Some(commit) = status_resp.ok
            .then_some(status_resp.data.as_ref())
            .flatten()
            .and_then(|d| d.get("base_commit"))
            .and_then(|v| v.as_str())
        {
            let short = if commit.len() > 8 { &commit[..8] } else { commit };
            self.base_commit = short.to_string();
        }

        // Fetch workspaces
        let ws_resp = self.client.list_workspaces().await?;
        if !ws_resp.ok {
            self.set_error(ws_resp.error.unwrap_or_else(|| "Failed to list workspaces".to_string()));
            return Ok(());
        }

        let new_workspaces: Vec<Workspace> = serde_json::from_value(ws_resp.data.unwrap_or_default())?;

        // Fetch analyses
        let an_resp = self.client.get_all_analyses().await?;
        if !an_resp.ok {
            self.set_error(an_resp.error.unwrap_or_else(|| "Failed to get analyses".to_string()));
            return Ok(());
        }

        let new_analyses: Vec<WorkspacePairAnalysis> = serde_json::from_value(an_resp.data.unwrap_or_default())?;

        let changed = self.workspaces.len() != new_workspaces.len()
            || self.analyses.len() != new_analyses.len()
            || !self.analyses_are_equal(&self.analyses, &new_analyses);

        if changed || self.view_state == ViewState::Loading {
            self.workspaces = new_workspaces;
            self.analyses = new_analyses;
            self.is_dirty = true;

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

    fn analyses_are_equal(&self, old: &[WorkspacePairAnalysis], new: &[WorkspacePairAnalysis]) -> bool {
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
    pub fn get_pairs_for_worktree(&self, id: &grove_lib::WorkspaceId) -> Vec<&WorkspacePairAnalysis> {
        self.analyses
            .iter()
            .filter(|a| {
                (a.workspace_a == *id || a.workspace_b == *id)
                    && a.score != OrthogonalityScore::Green
            })
            .collect()
    }
}
