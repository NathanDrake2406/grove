use crossterm::event::{KeyCode, KeyEvent};
use grove_cli::client::DaemonClient;
use grove_lib::{Workspace, WorkspacePairAnalysis};

#[derive(Debug)]
pub enum ViewState {
    Loading,
    NoWorktrees,
    Dashboard,
    PairDetail {
        analysis: WorkspacePairAnalysis,
    },
    Error(String),
}

// Implement partial eq manually for view state comparisons
impl PartialEq for ViewState {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Loading, Self::Loading) => true,
            (Self::NoWorktrees, Self::NoWorktrees) => true,
            (Self::Dashboard, Self::Dashboard) => true,
            (Self::PairDetail { analysis: a }, Self::PairDetail { analysis: b }) => {
                a.workspace_a == b.workspace_a && a.workspace_b == b.workspace_b
            }
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

    // Dashboard selection state
    pub selected_worktree_index: usize,
    pub selected_pair_index: usize,
}

impl App {
    pub fn new(client: DaemonClient) -> Self {
        Self {
            client,
            is_dirty: true,
            view_state: ViewState::Loading,
            workspaces: Vec::new(),
            analyses: Vec::new(),
            selected_worktree_index: 0,
            selected_pair_index: 0,
        }
    }

    /// Fetches the latest data from the daemon.
    pub async fn refresh_data(&mut self) -> Result<(), Box<dyn std::error::Error>> {
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

        // Detect if anything changed
        // For simplicity we use length + timestamp/content checks, or just compare JSON if derived traits are missing.
        // In a real app we might diff or store last_computed to be more precise, but over-writing with new Vecs
        // and setting is_dirty locally is fine.
        
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
        // Very basic structural check (time updated vs just same length).
        // Since the prompt specifies deterministic overlap computation, we will assume if the length matches it's close enough,
        // but to be precise we should compare `last_computed`.
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

    pub fn handle_input(&mut self, key: KeyEvent) -> bool {
        // Return true if we should exit
        match self.view_state {
            ViewState::Dashboard => self.handle_dashboard_input(key),
            ViewState::PairDetail { .. } => self.handle_detail_input(key),
            ViewState::Loading | ViewState::NoWorktrees | ViewState::Error(_) => {
                matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
            }
        }
    }

    fn handle_dashboard_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Char('j') | KeyCode::Down => {
                if !self.workspaces.is_empty() {
                    self.selected_worktree_index = (self.selected_worktree_index + 1).min(self.workspaces.len() - 1);
                    self.selected_pair_index = 0;
                    self.is_dirty = true;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.selected_worktree_index > 0 {
                    self.selected_worktree_index -= 1;
                    self.selected_pair_index = 0;
                    self.is_dirty = true;
                }
            }
            KeyCode::Enter => {
                // If they have selected a worktree, we find its conflicts
                if let Some(ws) = self.workspaces.get(self.selected_worktree_index) {
                    let pairs = self.get_pairs_for_worktree(&ws.id);
                    if let Some(selected_pair) = pairs.get(self.selected_pair_index) {
                        self.view_state = ViewState::PairDetail {
                            analysis: (*selected_pair).clone(),
                        };
                        self.is_dirty = true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    fn handle_detail_input(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Backspace => {
                self.view_state = ViewState::Dashboard;
                self.is_dirty = true;
                false
            }
            _ => false, // Could add pagination or scrolling within detail view later
        }
    }

    /// Gets all analyses where the given workspace ID is either workspace_a or workspace_b.
    /// Filters out pairs that have a Green score (no conflicts).
    pub fn get_pairs_for_worktree(&self, id: &grove_lib::WorkspaceId) -> Vec<&WorkspacePairAnalysis> {
        self.analyses
            .iter()
            .filter(|a| {
                (a.workspace_a == *id || a.workspace_b == *id)
                    && a.score != grove_lib::OrthogonalityScore::Green
            })
            .collect()
    }
}
