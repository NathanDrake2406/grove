use grove_lib::WorkspaceId;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use notify::{
    event::{CreateKind, ModifyKind, RemoveKind},
    Event, EventKind,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Configuration for the filesystem watcher.
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    pub debounce_ms: u64,
    pub circuit_breaker_threshold: usize,
    pub ignore_patterns: Vec<String>,
    pub respect_gitignore: bool,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 500,
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

/// Tracks per-worktree state for the debounce + circuit breaker.
struct WorktreeWatchState {
    workspace_id: WorkspaceId,
    root: PathBuf,
    gitignore: Option<Gitignore>,
    pending_changes: Vec<PathBuf>,
    last_flush: Instant,
}

impl WorktreeWatchState {
    fn new(workspace_id: WorkspaceId, root: PathBuf, gitignore: Option<Gitignore>) -> Self {
        Self {
            workspace_id,
            root,
            gitignore,
            pending_changes: Vec::new(),
            last_flush: Instant::now(),
        }
    }
}

/// Events produced by the watcher after debouncing.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// Individual file changes (normal path).
    FilesChanged {
        workspace_id: WorkspaceId,
        paths: Vec<PathBuf>,
    },
    /// Circuit breaker tripped — too many files changed at once.
    FullReindexNeeded {
        workspace_id: WorkspaceId,
    },
    /// Base branch ref changed.
    BaseRefChanged {
        ref_path: PathBuf,
    },
}

/// Builds a gitignore matcher for a worktree path.
pub fn build_gitignore(worktree_root: &Path) -> Option<Gitignore> {
    let gitignore_path = worktree_root.join(".gitignore");
    if !gitignore_path.exists() {
        return None;
    }

    let mut builder = GitignoreBuilder::new(worktree_root);
    builder.add(&gitignore_path);
    match builder.build() {
        Ok(gi) => Some(gi),
        Err(e) => {
            warn!(path = %gitignore_path.display(), error = %e, "failed to parse .gitignore");
            None
        }
    }
}

/// Checks if a path matches any of the hardcoded ignore patterns.
pub fn matches_ignore_pattern(path: &Path, patterns: &[String]) -> bool {
    let path_str = path.to_string_lossy();
    for pattern in patterns {
        if pattern.starts_with("*.") {
            // Extension pattern
            let ext = &pattern[1..]; // e.g., ".min.js"
            if path_str.ends_with(ext) {
                return true;
            }
        } else {
            // Directory/path component pattern
            for component in path.components() {
                if component.as_os_str().to_string_lossy() == *pattern {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks if a path should be ignored based on gitignore + hardcoded patterns.
pub fn should_ignore(
    path: &Path,
    worktree_root: &Path,
    gitignore: Option<&Gitignore>,
    patterns: &[String],
) -> bool {
    // Check hardcoded patterns first (fast path)
    if matches_ignore_pattern(path, patterns) {
        return true;
    }

    // Check gitignore
    if let Some(gi) = gitignore {
        let relative = path.strip_prefix(worktree_root).unwrap_or(path);
        let is_dir = path.is_dir();
        if gi.matched(relative, is_dir).is_ignore() {
            return true;
        }
    }

    false
}

/// Checks if a path is a git ref file that indicates base branch changes.
pub fn is_git_ref_change(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".git/refs/remotes/") || path_str.ends_with("FETCH_HEAD")
}

/// Determines which worktree a path belongs to based on registered worktree roots.
pub fn find_worktree_for_path<'a>(
    path: &Path,
    worktrees: &'a HashMap<WorkspaceId, PathBuf>,
) -> Option<(&'a WorkspaceId, &'a PathBuf)> {
    worktrees
        .iter()
        .filter(|(_, root)| path.starts_with(root))
        .max_by_key(|(_, root)| root.components().count())
}

/// Debouncer that collects filesystem events and flushes them in batches.
pub struct Debouncer {
    config: WatcherConfig,
    worktrees: HashMap<WorkspaceId, WorktreeWatchState>,
    git_dir: Option<PathBuf>,
}

impl Debouncer {
    pub fn new(config: WatcherConfig) -> Self {
        Self {
            config,
            worktrees: HashMap::new(),
            git_dir: None,
        }
    }

    /// Register a worktree to watch.
    pub fn register_worktree(
        &mut self,
        workspace_id: WorkspaceId,
        root: PathBuf,
    ) {
        let gitignore = if self.config.respect_gitignore {
            build_gitignore(&root)
        } else {
            None
        };
        self.worktrees.insert(
            workspace_id,
            WorktreeWatchState::new(workspace_id, root, gitignore),
        );
    }

    /// Unregister a worktree.
    pub fn unregister_worktree(&mut self, workspace_id: &WorkspaceId) {
        self.worktrees.remove(workspace_id);
    }

    /// Set the git directory to watch for ref changes.
    pub fn set_git_dir(&mut self, git_dir: PathBuf) {
        self.git_dir = Some(git_dir);
    }

    /// Process a raw filesystem event. Returns watch events if the debounce
    /// window has elapsed or the circuit breaker trips.
    pub fn process_event(&mut self, event: &Event) -> Vec<WatchEvent> {
        let mut output = Vec::new();

        // Only care about creates, modifies, and removes
        match event.kind {
            EventKind::Create(CreateKind::File)
            | EventKind::Modify(ModifyKind::Data(_))
            | EventKind::Modify(ModifyKind::Name(_))
            | EventKind::Remove(RemoveKind::File) => {}
            _ => return output,
        }

        for path in &event.paths {
            // Check for git ref changes
            if is_git_ref_change(path) {
                output.push(WatchEvent::BaseRefChanged {
                    ref_path: path.clone(),
                });
                continue;
            }

            // Find which worktree this path belongs to
            let worktree_roots: HashMap<WorkspaceId, PathBuf> = self
                .worktrees
                .iter()
                .map(|(id, state)| (*id, state.root.clone()))
                .collect();

            if let Some((ws_id, _root)) = find_worktree_for_path(path, &worktree_roots) {
                let ws_id = *ws_id;
                if let Some(state) = self.worktrees.get_mut(&ws_id) {
                    // Check ignore patterns
                    if should_ignore(
                        path,
                        &state.root,
                        state.gitignore.as_ref(),
                        &self.config.ignore_patterns,
                    ) {
                        debug!(path = %path.display(), "ignoring path");
                        continue;
                    }

                    state.pending_changes.push(path.clone());

                    // Circuit breaker check
                    if state.pending_changes.len() >= self.config.circuit_breaker_threshold {
                        info!(
                            workspace_id = %ws_id,
                            count = state.pending_changes.len(),
                            "circuit breaker tripped, requesting full re-index"
                        );
                        state.pending_changes.clear();
                        state.last_flush = Instant::now();
                        output.push(WatchEvent::FullReindexNeeded {
                            workspace_id: ws_id,
                        });
                    }
                }
            }
        }

        output
    }

    /// Flush any worktrees whose debounce window has elapsed.
    /// Call this periodically (e.g., every 100ms).
    pub fn flush_debounced(&mut self) -> Vec<WatchEvent> {
        let mut output = Vec::new();
        let debounce_duration = Duration::from_millis(self.config.debounce_ms);
        let now = Instant::now();

        for state in self.worktrees.values_mut() {
            if !state.pending_changes.is_empty()
                && now.duration_since(state.last_flush) >= debounce_duration
            {
                let paths: Vec<PathBuf> = state.pending_changes.drain(..).collect();
                // Deduplicate
                let mut unique_paths: Vec<PathBuf> = paths;
                unique_paths.sort();
                unique_paths.dedup();

                debug!(
                    workspace_id = %state.workspace_id,
                    count = unique_paths.len(),
                    "flushing debounced changes"
                );

                output.push(WatchEvent::FilesChanged {
                    workspace_id: state.workspace_id,
                    paths: unique_paths,
                });
                state.last_flush = now;
            }
        }

        output
    }

    /// Get the number of pending (undebounced) changes for a worktree.
    pub fn pending_count(&self, workspace_id: &WorkspaceId) -> usize {
        self.worktrees
            .get(workspace_id)
            .map_or(0, |s| s.pending_changes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, DataChange, ModifyKind};
    use std::fs;
    use uuid::Uuid;

    fn make_create_event(paths: Vec<PathBuf>) -> Event {
        Event {
            kind: EventKind::Create(CreateKind::File),
            paths,
            attrs: Default::default(),
        }
    }

    fn make_modify_event(paths: Vec<PathBuf>) -> Event {
        Event {
            kind: EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            paths,
            attrs: Default::default(),
        }
    }

    #[test]
    fn ignores_node_modules() {
        let patterns = vec!["node_modules".to_string()];
        let path = PathBuf::from("/project/node_modules/foo/bar.js");
        assert!(matches_ignore_pattern(&path, &patterns));
    }

    #[test]
    fn ignores_extension_patterns() {
        let patterns = vec!["*.min.js".to_string(), "*.map".to_string()];
        assert!(matches_ignore_pattern(
            &PathBuf::from("/project/bundle.min.js"),
            &patterns
        ));
        assert!(matches_ignore_pattern(
            &PathBuf::from("/project/app.js.map"),
            &patterns
        ));
        assert!(!matches_ignore_pattern(
            &PathBuf::from("/project/app.js"),
            &patterns
        ));
    }

    #[test]
    fn does_not_ignore_normal_files() {
        let patterns = vec!["node_modules".to_string(), "target".to_string()];
        assert!(!matches_ignore_pattern(
            &PathBuf::from("/project/src/main.rs"),
            &patterns
        ));
    }

    #[test]
    fn detects_git_ref_changes() {
        assert!(is_git_ref_change(&PathBuf::from(
            "/project/.git/refs/remotes/origin/main"
        )));
        assert!(is_git_ref_change(&PathBuf::from(
            "/project/.git/FETCH_HEAD"
        )));
        assert!(!is_git_ref_change(&PathBuf::from(
            "/project/src/main.rs"
        )));
    }

    #[test]
    fn finds_worktree_for_path() {
        let mut worktrees = HashMap::new();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        worktrees.insert(id_a, PathBuf::from("/worktrees/alpha"));
        worktrees.insert(id_b, PathBuf::from("/worktrees/beta"));

        let result = find_worktree_for_path(
            &PathBuf::from("/worktrees/alpha/src/main.rs"),
            &worktrees,
        );
        assert!(result.is_some());
        assert_eq!(*result.unwrap().0, id_a);

        let result = find_worktree_for_path(
            &PathBuf::from("/somewhere/else/main.rs"),
            &worktrees,
        );
        assert!(result.is_none());
    }

    #[test]
    fn debouncer_collects_changes() {
        let config = WatcherConfig {
            debounce_ms: 500,
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let event = make_modify_event(vec![PathBuf::from("/worktrees/test/src/main.rs")]);
        let immediate = debouncer.process_event(&event);
        // Should not produce events immediately (debouncing)
        assert!(immediate.is_empty());

        assert_eq!(debouncer.pending_count(&ws_id), 1);
    }

    #[test]
    fn debouncer_ignores_filtered_paths() {
        let config = WatcherConfig {
            debounce_ms: 500,
            ignore_patterns: vec!["node_modules".to_string()],
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let event = make_create_event(vec![PathBuf::from(
            "/worktrees/test/node_modules/pkg/index.js",
        )]);
        debouncer.process_event(&event);

        assert_eq!(debouncer.pending_count(&ws_id), 0);
    }

    #[test]
    fn circuit_breaker_trips_at_threshold() {
        let config = WatcherConfig {
            debounce_ms: 500,
            circuit_breaker_threshold: 3,
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        // Send 3 file events — should trip the circuit breaker
        for i in 0..3 {
            let event = make_modify_event(vec![PathBuf::from(format!(
                "/worktrees/test/src/file{i}.rs"
            ))]);
            let events = debouncer.process_event(&event);
            if i == 2 {
                assert_eq!(events.len(), 1);
                match &events[0] {
                    WatchEvent::FullReindexNeeded { workspace_id } => {
                        assert_eq!(*workspace_id, ws_id);
                    }
                    other => panic!("expected FullReindexNeeded, got {other:?}"),
                }
            }
        }

        // Pending should be cleared after circuit breaker
        assert_eq!(debouncer.pending_count(&ws_id), 0);
    }

    #[test]
    fn git_ref_change_produces_event() {
        let config = WatcherConfig::default();
        let mut debouncer = Debouncer::new(config);

        let event = make_modify_event(vec![PathBuf::from(
            "/project/.git/refs/remotes/origin/main",
        )]);
        let events = debouncer.process_event(&event);

        assert_eq!(events.len(), 1);
        match &events[0] {
            WatchEvent::BaseRefChanged { ref_path } => {
                assert!(ref_path.to_string_lossy().contains("origin/main"));
            }
            other => panic!("expected BaseRefChanged, got {other:?}"),
        }
    }

    #[test]
    fn flush_deduplicates_paths() {
        let config = WatcherConfig {
            debounce_ms: 0, // Flush immediately
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        // Same file changed twice
        let event = make_modify_event(vec![PathBuf::from("/worktrees/test/src/main.rs")]);
        debouncer.process_event(&event);
        debouncer.process_event(&event);

        assert_eq!(debouncer.pending_count(&ws_id), 2);

        // Flush should deduplicate
        let events = debouncer.flush_debounced();
        assert_eq!(events.len(), 1);
        match &events[0] {
            WatchEvent::FilesChanged { paths, .. } => {
                assert_eq!(paths.len(), 1); // Deduplicated
            }
            other => panic!("expected FilesChanged, got {other:?}"),
        }
    }

    #[test]
    fn gitignore_filtering() {
        let dir = std::env::temp_dir().join(format!("grove-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(".gitignore"), "*.log\nbuild/\n").unwrap();

        let gi = build_gitignore(&dir).unwrap();

        // .log files should be ignored
        assert!(should_ignore(
            &dir.join("debug.log"),
            &dir,
            Some(&gi),
            &[],
        ));

        // .rs files should not be ignored
        assert!(!should_ignore(
            &dir.join("src/main.rs"),
            &dir,
            Some(&gi),
            &[],
        ));

        // Cleanup
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unregister_worktree_stops_tracking() {
        let config = WatcherConfig::default();
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let event = make_modify_event(vec![PathBuf::from("/worktrees/test/src/main.rs")]);
        debouncer.process_event(&event);
        assert_eq!(debouncer.pending_count(&ws_id), 1);

        debouncer.unregister_worktree(&ws_id);
        assert_eq!(debouncer.pending_count(&ws_id), 0);
    }

    #[test]
    fn process_event_with_empty_paths_list_is_noop() {
        let config = WatcherConfig::default();
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let event = make_modify_event(vec![]);
        let events = debouncer.process_event(&event);
        assert!(events.is_empty());
        assert_eq!(debouncer.pending_count(&ws_id), 0);
    }

    #[test]
    fn process_event_for_unregistered_path_is_ignored() {
        let config = WatcherConfig::default();
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/known"));

        let event = make_modify_event(vec![PathBuf::from("/outside/root/src/main.rs")]);
        let events = debouncer.process_event(&event);
        assert!(events.is_empty());
        assert_eq!(debouncer.pending_count(&ws_id), 0);
    }

    #[test]
    fn find_worktree_prefers_most_specific_root() {
        let mut worktrees = HashMap::new();
        let parent = Uuid::new_v4();
        let nested = Uuid::new_v4();
        worktrees.insert(parent, PathBuf::from("/worktrees/mono"));
        worktrees.insert(nested, PathBuf::from("/worktrees/mono/service-a"));

        let result = find_worktree_for_path(
            &PathBuf::from("/worktrees/mono/service-a/src/lib.rs"),
            &worktrees,
        )
        .expect("path should resolve to a worktree");
        assert_eq!(*result.0, nested);
    }

    #[test]
    fn flush_respects_debounce_window() {
        let config = WatcherConfig {
            debounce_ms: 60,
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));
        debouncer.process_event(&make_modify_event(vec![PathBuf::from(
            "/worktrees/test/src/main.rs",
        )]));

        assert!(debouncer.flush_debounced().is_empty());
        std::thread::sleep(std::time::Duration::from_millis(75));

        let flushed = debouncer.flush_debounced();
        assert_eq!(flushed.len(), 1);
        match &flushed[0] {
            WatchEvent::FilesChanged { workspace_id, paths } => {
                assert_eq!(*workspace_id, ws_id);
                assert_eq!(paths, &vec![PathBuf::from("/worktrees/test/src/main.rs")]);
            }
            other => panic!("expected FilesChanged, got {other:?}"),
        }
    }

    #[test]
    fn unregister_worktree_discards_pending_changes_before_flush() {
        let config = WatcherConfig {
            debounce_ms: 0,
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));
        debouncer.process_event(&make_modify_event(vec![PathBuf::from(
            "/worktrees/test/src/main.rs",
        )]));
        assert_eq!(debouncer.pending_count(&ws_id), 1);

        debouncer.unregister_worktree(&ws_id);
        assert!(debouncer.flush_debounced().is_empty());
    }

    #[test]
    fn circuit_breaker_with_many_paths_in_one_event_leaves_tail_pending() {
        let config = WatcherConfig {
            debounce_ms: 0,
            circuit_breaker_threshold: 2,
            ..Default::default()
        };
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let events = debouncer.process_event(&make_modify_event(vec![
            PathBuf::from("/worktrees/test/src/a.rs"),
            PathBuf::from("/worktrees/test/src/b.rs"),
            PathBuf::from("/worktrees/test/src/c.rs"),
        ]));
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            WatchEvent::FullReindexNeeded { workspace_id } if *workspace_id == ws_id
        ));
        assert_eq!(debouncer.pending_count(&ws_id), 1);

        let flush_events = debouncer.flush_debounced();
        assert_eq!(flush_events.len(), 1);
        match &flush_events[0] {
            WatchEvent::FilesChanged { paths, .. } => {
                assert_eq!(paths, &vec![PathBuf::from("/worktrees/test/src/c.rs")]);
            }
            other => panic!("expected FilesChanged, got {other:?}"),
        }
    }

    #[test]
    fn mixed_git_ref_and_file_paths_emit_base_event_and_keep_pending_file() {
        let config = WatcherConfig::default();
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let events = debouncer.process_event(&make_modify_event(vec![
            PathBuf::from("/repo/.git/refs/remotes/origin/main"),
            PathBuf::from("/worktrees/test/src/main.rs"),
        ]));
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], WatchEvent::BaseRefChanged { .. }));
        assert_eq!(debouncer.pending_count(&ws_id), 1);
    }

    #[test]
    fn directory_create_event_is_ignored() {
        let config = WatcherConfig::default();
        let mut debouncer = Debouncer::new(config);
        let ws_id = Uuid::new_v4();
        debouncer.register_worktree(ws_id, PathBuf::from("/worktrees/test"));

        let event = Event {
            kind: EventKind::Create(CreateKind::Folder),
            paths: vec![PathBuf::from("/worktrees/test/src/new-dir")],
            attrs: Default::default(),
        };
        let events = debouncer.process_event(&event);
        assert!(events.is_empty());
        assert_eq!(debouncer.pending_count(&ws_id), 0);
    }
}
