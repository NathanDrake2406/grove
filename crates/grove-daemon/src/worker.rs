use crate::state::{GroveConfig, StateMessage};
use chrono::Utc;
use grove_lib::changeset::{ContentChange, build_workspace_changeset};
use grove_lib::fs::GitObjectFileSystem;
use grove_lib::graph::{ImportGraph, build_import_graph_from_paths, compute_dependency_overlaps};
use grove_lib::languages::LanguageRegistry;
use grove_lib::scorer;
use grove_lib::{ChangeType, Workspace, WorkspaceChangeset, WorkspacePairAnalysis};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub enum WorkerMessage {
    AnalyzePair {
        workspace_a: Workspace,
        workspace_b: Workspace,
        base_graph: Arc<ImportGraph>,
    },
}

pub struct WorkerPool {
    tx: mpsc::Sender<WorkerMessage>,
    handle: JoinHandle<()>,
}

impl WorkerPool {
    pub fn sender(&self) -> mpsc::Sender<WorkerMessage> {
        self.tx.clone()
    }

    pub async fn shutdown(self) {
        drop(self.tx);
        if let Err(e) = self.handle.await {
            warn!(error = %e, "worker pool join failed");
        }
    }
}

pub fn spawn_worker_pool(config: GroveConfig, state_tx: mpsc::Sender<StateMessage>) -> WorkerPool {
    let (tx, mut rx) = mpsc::channel(256);
    let worker_count = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2)
        .clamp(1, 8);

    let handle = tokio::spawn(async move {
        let semaphore = Arc::new(Semaphore::new(worker_count));
        let mut in_flight = tokio::task::JoinSet::new();

        info!(worker_count, "worker pool started");

        while let Some(msg) = rx.recv().await {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => break,
            };

            let task_state_tx = state_tx.clone();
            let task_config = config.clone();
            in_flight.spawn(async move {
                let _permit = permit;
                process_message(msg, task_config, task_state_tx).await;
            });
        }

        in_flight.abort_all();
        while in_flight.join_next().await.is_some() {}
        info!("worker pool stopped");
    });

    WorkerPool { tx, handle }
}

async fn process_message(
    msg: WorkerMessage,
    config: GroveConfig,
    state_tx: mpsc::Sender<StateMessage>,
) {
    match msg {
        WorkerMessage::AnalyzePair {
            workspace_a,
            workspace_b,
            base_graph,
        } => {
            let timeout_ms = config.analysis_timeout_ms;
            let timeout_duration = Duration::from_millis(timeout_ms);
            let a_id = workspace_a.id;
            let b_id = workspace_b.id;
            let analysis_config = config.clone();

            let result = timeout(
                timeout_duration,
                tokio::task::spawn_blocking(move || {
                    analyze_workspace_pair(
                        &analysis_config,
                        &workspace_a,
                        &workspace_b,
                        &base_graph,
                    )
                }),
            )
            .await;

            match result {
                Ok(join_result) => match join_result {
                    Ok(Ok(analysis)) => {
                        if let Err(e) = state_tx
                            .send(StateMessage::AnalysisComplete {
                                pair: canonical_pair(a_id, b_id),
                                result: analysis,
                            })
                            .await
                        {
                            warn!(
                                workspace_a = %a_id,
                                workspace_b = %b_id,
                                error = %e,
                                "failed to send analysis result to state actor"
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(
                            workspace_a = %a_id,
                            workspace_b = %b_id,
                            error = %e,
                            "pair analysis failed"
                        );
                        notify_analysis_failure(&state_tx, a_id, b_id, "pair analysis failed")
                            .await;
                    }
                    Err(e) => {
                        error!(
                            workspace_a = %a_id,
                            workspace_b = %b_id,
                            error = %e,
                            "worker task panicked"
                        );
                        notify_analysis_failure(&state_tx, a_id, b_id, "worker task panicked")
                            .await;
                    }
                },
                Err(_) => {
                    warn!(
                        workspace_a = %a_id,
                        workspace_b = %b_id,
                        timeout_ms,
                        "pair analysis timed out"
                    );
                    notify_analysis_failure(&state_tx, a_id, b_id, "pair analysis timed out").await;
                }
            }
        }
    }
}

pub(crate) fn analyze_workspace_pair(
    config: &GroveConfig,
    workspace_a: &Workspace,
    workspace_b: &Workspace,
    base_graph: &ImportGraph,
) -> Result<WorkspacePairAnalysis, WorkerError> {
    let registry = LanguageRegistry::with_defaults();
    let changes_a = extract_changeset(config, &registry, workspace_a)?;
    let changes_b = extract_changeset(config, &registry, workspace_b)?;

    let dependency_overlaps = compute_dependency_overlaps(&changes_a, &changes_b, base_graph);
    let analysis = scorer::score_pair(&changes_a, &changes_b, dependency_overlaps, Utc::now());

    info!(
        workspace_a = %workspace_a.id,
        workspace_b = %workspace_b.id,
        score = ?analysis.score,
        overlaps = analysis.overlaps.len(),
        "pair analysis computed"
    );

    Ok(analysis)
}

/// Build the base-branch import graph for a workspace repository.
///
/// The graph is built from the configured base branch tree (or workspace base_ref
/// when present) so dependency overlap detection can trace changed exports through
/// dependents even before a merge is attempted.
pub(crate) fn build_base_graph_from_workspace(
    config: &GroveConfig,
    workspace: &Workspace,
) -> Result<(ImportGraph, String), WorkerError> {
    use crate::git::GitRepo;

    let base_ref = if workspace.base_ref.is_empty() {
        config.base_branch.as_str()
    } else {
        workspace.base_ref.as_str()
    };

    let git = GitRepo::open(&workspace.path)?;
    let base_commit = git.resolve_oid(base_ref)?.to_hex().to_string();
    let base_tree = git.resolve_tree(base_ref)?;
    let records = base_tree
        .traverse()
        .breadthfirst
        .files()
        .map_err(|err| WorkerError::Gix {
            context: "tree traversal",
            repo_path: workspace.path.clone(),
            detail: err.to_string(),
        })?;
    let file_paths: Vec<PathBuf> = records
        .into_iter()
        .filter(|entry| !entry.mode.is_tree())
        .map(|entry| PathBuf::from(entry.filepath.to_string()))
        .collect();

    let file_system =
        GitObjectFileSystem::open(&workspace.path, base_ref).map_err(|err| WorkerError::Gix {
            context: "git object filesystem",
            repo_path: workspace.path.clone(),
            detail: err.to_string(),
        })?;
    let registry = LanguageRegistry::with_defaults();
    let max_file_size_bytes = config.max_file_size_kb.saturating_mul(1024);
    let graph =
        build_import_graph_from_paths(&file_system, &registry, &file_paths, max_file_size_bytes);

    Ok((graph, base_commit))
}

fn extract_changeset(
    config: &GroveConfig,
    registry: &LanguageRegistry,
    workspace: &Workspace,
) -> Result<WorkspaceChangeset, WorkerError> {
    use crate::git::GitRepo;

    let base_ref = if workspace.base_ref.is_empty() {
        config.base_branch.as_str()
    } else {
        workspace.base_ref.as_str()
    };

    let git = GitRepo::open(&workspace.path)?;

    // Phase 2A: merge-base via gix (was subprocess)
    let merge_base = git.merge_base("HEAD", base_ref)?;

    // ahead/behind: kept as subprocess (runs once, ~2ms, not worth graph walk complexity)
    let ahead_behind = git_output_line(
        &workspace.path,
        [
            "rev-list",
            "--left-right",
            "--count",
            &format!("{base_ref}...HEAD"),
        ],
        "rev-list --left-right --count",
    )
    .ok()
    .and_then(|line| parse_left_right_counts(&line))
    .unwrap_or((0, 0));

    // Phase 2B: diff name-status via gix tree diff (was subprocess)
    let base_tree = git.resolve_tree(&merge_base)?;
    let head_tree = git.resolve_tree("HEAD")?;
    let statuses = git.diff_name_status(&base_tree, &head_tree)?;

    // Merge in working-tree dirty files not already in the committed diff.
    // This catches files that are modified on disk but not yet committed.
    let wt_statuses = git.worktree_status().unwrap_or_default();
    let mut statuses = statuses;
    let committed_paths: std::collections::HashSet<PathBuf> =
        statuses.iter().map(|s| s.path.clone()).collect();
    for wt in wt_statuses {
        if !committed_paths.contains(&wt.path) {
            statuses.push(wt);
        }
    }

    // Phase 1: resolve trees once, reuse for all blob reads (was 2N subprocesses)
    let mut base_tree_mut = git.resolve_tree(&merge_base)?;
    let mut head_tree_mut = git.resolve_tree("HEAD")?;

    let mut changes = Vec::new();
    let max_file_size_bytes = config.max_file_size_kb * 1024;

    for status in statuses {
        let old_path = status.old_path.as_deref().unwrap_or(status.path.as_path());
        let new_path = status.path.as_path();

        // Phase 1: read blobs in-process (was git show subprocess per file)
        let old_content = match status.change_type {
            ChangeType::Added => None,
            ChangeType::Modified | ChangeType::Deleted | ChangeType::Renamed => {
                git.read_blob(&mut base_tree_mut, old_path)
            }
        };

        // Read new-side from working tree (disk), falling back to HEAD blob.
        // This captures uncommitted changes that the watcher triggered on.
        let new_content = match status.change_type {
            ChangeType::Deleted => None,
            ChangeType::Added | ChangeType::Modified | ChangeType::Renamed => {
                let disk_path = workspace.path.join(new_path);
                std::fs::read(&disk_path)
                    .ok()
                    .or_else(|| git.read_blob(&mut head_tree_mut, new_path))
            }
        };

        changes.push(ContentChange {
            path: status.path,
            old_path: status.old_path,
            change_type: status.change_type,
            old_content,
            new_content,
        });
    }

    Ok(build_workspace_changeset(
        registry,
        workspace.id,
        merge_base,
        ahead_behind.1,
        ahead_behind.0,
        changes,
        max_file_size_bytes,
    ))
}

fn parse_left_right_counts(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split_whitespace();
    let left = parts.next()?.parse::<u32>().ok()?;
    let right = parts.next()?.parse::<u32>().ok()?;
    Some((left, right))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiffFileStatus {
    pub(crate) path: PathBuf,
    pub(crate) old_path: Option<PathBuf>,
    pub(crate) change_type: ChangeType,
}

pub(crate) fn git_output_line<const N: usize>(
    repo_path: &Path,
    args: [&str; N],
    context: &'static str,
) -> Result<String, WorkerError> {
    let output = git_output(repo_path, args, context)?;
    Ok(output.lines().next().unwrap_or_default().trim().to_string())
}

pub(crate) fn git_output<const N: usize>(
    repo_path: &Path,
    args: [&str; N],
    context: &'static str,
) -> Result<String, WorkerError> {
    let output = git_output_bytes(repo_path, args, context)?;
    String::from_utf8(output).map_err(|source| WorkerError::InvalidUtf8 {
        context,
        repo_path: repo_path.to_path_buf(),
        source,
    })
}

pub(crate) fn git_output_bytes<const N: usize>(
    repo_path: &Path,
    args: [&str; N],
    context: &'static str,
) -> Result<Vec<u8>, WorkerError> {
    let output = Command::new("git")
        .current_dir(repo_path)
        .args(args)
        .output()
        .map_err(|source| WorkerError::GitIo {
            context,
            source,
            repo_path: repo_path.to_path_buf(),
        })?;

    if !output.status.success() {
        return Err(WorkerError::GitFailed {
            context,
            repo_path: repo_path.to_path_buf(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(output.stdout)
}

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("git io failed during {context} in {repo_path}: {source}")]
    GitIo {
        context: &'static str,
        repo_path: PathBuf,
        source: std::io::Error,
    },
    #[error("git command failed during {context} in {repo_path}: {stderr}")]
    GitFailed {
        context: &'static str,
        repo_path: PathBuf,
        stderr: String,
    },
    #[error("invalid utf8 during {context} in {repo_path}: {source}")]
    InvalidUtf8 {
        context: &'static str,
        repo_path: PathBuf,
        source: std::string::FromUtf8Error,
    },
    #[error("gix error during {context} in {repo_path}: {detail}")]
    Gix {
        context: &'static str,
        repo_path: PathBuf,
        detail: String,
    },
}

/// Notify the state actor that a pair analysis failed so it can clean up
/// the `in_flight_pairs` entry and unblock any `AwaitAnalysis` waiters.
async fn notify_analysis_failure(
    state_tx: &mpsc::Sender<StateMessage>,
    a_id: grove_lib::WorkspaceId,
    b_id: grove_lib::WorkspaceId,
    reason: &str,
) {
    if let Err(e) = state_tx
        .send(StateMessage::AnalysisFailure {
            pair: canonical_pair(a_id, b_id),
        })
        .await
    {
        warn!(
            workspace_a = %a_id,
            workspace_b = %b_id,
            error = %e,
            reason,
            "failed to notify state actor of analysis failure"
        );
    }
}

pub(crate) fn canonical_pair(
    a: grove_lib::WorkspaceId,
    b: grove_lib::WorkspaceId,
) -> (grove_lib::WorkspaceId, grove_lib::WorkspaceId) {
    if a <= b { (a, b) } else { (b, a) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use grove_lib::{MergeOrder, OrthogonalityScore, WorkspaceMetadata};
    use tempfile::tempdir;
    use uuid::Uuid;

    fn run_git(repo: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .expect("git command should run");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dirs should be created");
        }
        std::fs::write(path, content).expect("file should be written");
    }

    fn make_workspace(path: PathBuf, branch: &str) -> Workspace {
        Workspace {
            id: Uuid::new_v4(),
            name: branch.to_string(),
            branch: branch.to_string(),
            path,
            base_ref: "main".to_string(),
            created_at: Utc::now(),
            last_activity: Utc::now(),
            metadata: WorkspaceMetadata::default(),
        }
    }

    fn init_repo_with_main(repo: &Path) {
        run_git(repo, &["init", "-b", "main"]);
        run_git(repo, &["config", "user.email", "grove@example.com"]);
        run_git(repo, &["config", "user.name", "Grove Tests"]);
    }

    fn add_worktree_from_main(
        repo: &Path,
        root: &Path,
        folder_name: &str,
        branch: &str,
    ) -> PathBuf {
        let worktree = root.join(folder_name);
        run_git(
            repo,
            &[
                "worktree",
                "add",
                worktree.to_str().expect("path should be utf8"),
                "-b",
                branch,
                "main",
            ],
        );
        run_git(&worktree, &["config", "user.email", "grove@example.com"]);
        run_git(&worktree, &["config", "user.name", "Grove Tests"]);
        worktree
    }

    fn default_config() -> GroveConfig {
        GroveConfig {
            base_branch: "main".to_string(),
            ..GroveConfig::default()
        }
    }

    fn assert_score_at_most_yellow(case_name: &str, analysis: &WorkspacePairAnalysis) {
        assert!(
            analysis.score <= OrthogonalityScore::Yellow,
            "{case_name}: expected score <= Yellow, got {:?} with overlaps {:?}",
            analysis.score,
            analysis.overlaps
        );
    }

    fn assert_no_symbol_or_schema_overlaps(case_name: &str, analysis: &WorkspacePairAnalysis) {
        let has_symbol_or_schema = analysis.overlaps.iter().any(|overlap| {
            matches!(
                overlap,
                grove_lib::Overlap::Symbol { .. } | grove_lib::Overlap::Schema { .. }
            )
        });
        assert!(
            !has_symbol_or_schema,
            "{case_name}: expected no symbol/schema overlaps, got {:?}",
            analysis.overlaps
        );
    }

    #[test]
    fn parse_left_right_counts_handles_valid_and_invalid_inputs() {
        assert_eq!(parse_left_right_counts("3 7"), Some((3, 7)));
        assert_eq!(parse_left_right_counts("0 0"), Some((0, 0)));
        assert_eq!(parse_left_right_counts("3"), None);
        assert_eq!(parse_left_right_counts("a b"), None);
        assert_eq!(parse_left_right_counts("3 b"), None);
    }

    #[test]
    fn git_output_bytes_returns_git_failed_for_invalid_git_command() {
        let repo = tempdir().unwrap();
        run_git(repo.path(), &["init", "-b", "main"]);
        run_git(repo.path(), &["config", "user.email", "grove@example.com"]);
        run_git(repo.path(), &["config", "user.name", "Grove Tests"]);

        let err =
            git_output_bytes(repo.path(), ["not-a-git-subcommand"], "invalid git").unwrap_err();
        assert!(matches!(err, WorkerError::GitFailed { .. }));
    }

    #[test]
    fn canonical_pair_orders_workspace_ids() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let pair = canonical_pair(a, b);
        assert!(pair.0 <= pair.1);
        assert_eq!(pair, canonical_pair(b, a));
    }

    #[test]
    fn analyze_workspace_pair_scores_shared_file_changes() {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");

        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "grove@example.com"]);
        run_git(&repo, &["config", "user.name", "Grove Tests"]);

        write_file(
            &repo.join("src/lib.rs"),
            "pub fn calc(v: i32) -> i32 {\n    v + 1\n}\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        run_git(&repo, &["checkout", "-b", "feat/a"]);
        write_file(
            &repo.join("src/lib.rs"),
            "pub fn calc(v: i32) -> i32 {\n    v + 2\n}\n",
        );
        run_git(&repo, &["commit", "-am", "feat a"]);

        let wt_b = temp.path().join("wt-b");
        run_git(
            &repo,
            &[
                "worktree",
                "add",
                wt_b.to_str().expect("path should be utf8"),
                "-b",
                "feat/b",
                "main",
            ],
        );
        run_git(&wt_b, &["config", "user.email", "grove@example.com"]);
        run_git(&wt_b, &["config", "user.name", "Grove Tests"]);

        write_file(
            &wt_b.join("src/lib.rs"),
            "pub fn calc(v: i32) -> i32 {\n    v + 3\n}\n",
        );
        run_git(&wt_b, &["commit", "-am", "feat b"]);

        let ws_a = make_workspace(repo.clone(), "feat/a");
        let ws_b = make_workspace(wt_b.clone(), "feat/b");

        let config = GroveConfig {
            base_branch: "main".to_string(),
            ..GroveConfig::default()
        };

        let analysis = analyze_workspace_pair(&config, &ws_a, &ws_b, &ImportGraph::new())
            .expect("analysis should succeed");

        assert_eq!(analysis.workspace_a, ws_a.id);
        assert_eq!(analysis.workspace_b, ws_b.id);
        assert!(analysis.score >= OrthogonalityScore::Yellow);
        assert!(
            analysis
                .overlaps
                .iter()
                .any(|overlap| matches!(overlap, grove_lib::Overlap::File { path, .. } if path == &PathBuf::from("src/lib.rs")))
        );
        assert!(matches!(
            analysis.merge_order_hint,
            MergeOrder::AFirst
                | MergeOrder::BFirst
                | MergeOrder::NeedsCoordination
                | MergeOrder::Either
        ));
    }

    #[test]
    fn analyze_workspace_pair_scoped_same_name_methods_do_not_escalate_to_red() {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");
        init_repo_with_main(&repo);

        let base_source = r#"
pub struct Auth;

impl Auth {
    pub fn handle(&self, token: &str) -> bool {
        !token.is_empty()
    }
}

pub struct Billing;

impl Billing {
    pub fn handle(&self, amount: u64) -> bool {
        amount > 0
    }
}
"#;
        write_file(&repo.join("src/lib.rs"), base_source);
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        run_git(&repo, &["checkout", "-b", "feat/a"]);
        let a_source = r#"
pub struct Auth;

impl Auth {
    pub fn handle(&self, token: &str) -> bool {
        token.starts_with("tok_")
    }
}

pub struct Billing;

impl Billing {
    pub fn handle(&self, amount: u64) -> bool {
        amount > 0
    }
}
"#;
        write_file(&repo.join("src/lib.rs"), a_source);
        run_git(&repo, &["commit", "-am", "feat a"]);

        let wt_b = add_worktree_from_main(&repo, temp.path(), "wt-b-symbol", "feat/b-symbol");
        let b_source = r#"
pub struct Auth;

impl Auth {
    pub fn handle(&self, token: &str) -> bool {
        !token.is_empty()
    }
}

pub struct Billing;

impl Billing {
    pub fn handle(&self, amount: u64) -> bool {
        amount >= 1
    }
}
"#;
        write_file(&wt_b.join("src/lib.rs"), b_source);
        run_git(&wt_b, &["commit", "-am", "feat b"]);

        let ws_a = make_workspace(repo.clone(), "feat/a");
        let ws_b = make_workspace(wt_b.clone(), "feat/b-symbol");
        let analysis = analyze_workspace_pair(&default_config(), &ws_a, &ws_b, &ImportGraph::new())
            .expect("analysis should succeed");

        assert_score_at_most_yellow("scoped_same_name_methods", &analysis);
        assert_no_symbol_or_schema_overlaps("scoped_same_name_methods", &analysis);
    }

    #[test]
    fn analyze_workspace_pair_docs_route_keywords_do_not_create_schema_overlap() {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");
        init_repo_with_main(&repo);

        write_file(&repo.join("README.md"), "base\n");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        run_git(&repo, &["checkout", "-b", "feat/a"]);
        write_file(
            &repo.join("docs/router-guide.md"),
            "# Router guide\nIndependent docs change.\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "feat a docs"]);

        let wt_b = add_worktree_from_main(&repo, temp.path(), "wt-b-route", "feat/b-route");
        write_file(
            &wt_b.join("docs/router-patterns.md"),
            "# Router patterns\nAnother independent docs change.\n",
        );
        run_git(&wt_b, &["add", "."]);
        run_git(&wt_b, &["commit", "-m", "feat b docs"]);

        let ws_a = make_workspace(repo.clone(), "feat/a");
        let ws_b = make_workspace(wt_b.clone(), "feat/b-route");
        let analysis = analyze_workspace_pair(&default_config(), &ws_a, &ws_b, &ImportGraph::new())
            .expect("analysis should succeed");

        assert_eq!(
            analysis.score,
            OrthogonalityScore::Green,
            "route keyword-only docs should stay green: {:?}",
            analysis.overlaps
        );
        assert_no_symbol_or_schema_overlaps("route_keyword_docs", &analysis);
    }

    #[test]
    fn analyze_workspace_pair_docs_migration_keywords_do_not_create_schema_overlap() {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");
        init_repo_with_main(&repo);

        write_file(&repo.join("README.md"), "base\n");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        run_git(&repo, &["checkout", "-b", "feat/a"]);
        write_file(
            &repo.join("docs/migrations-playbook.md"),
            "# Migrations playbook\nIndependent docs change.\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "feat a docs"]);

        let wt_b = add_worktree_from_main(&repo, temp.path(), "wt-b-migration", "feat/b-migration");
        write_file(
            &wt_b.join("notes/migrations-changelog.md"),
            "# Migration changelog\nAnother independent docs change.\n",
        );
        run_git(&wt_b, &["add", "."]);
        run_git(&wt_b, &["commit", "-m", "feat b docs"]);

        let ws_a = make_workspace(repo.clone(), "feat/a");
        let ws_b = make_workspace(wt_b.clone(), "feat/b-migration");
        let analysis = analyze_workspace_pair(&default_config(), &ws_a, &ws_b, &ImportGraph::new())
            .expect("analysis should succeed");

        assert_eq!(
            analysis.score,
            OrthogonalityScore::Green,
            "migration keyword-only docs should stay green: {:?}",
            analysis.overlaps
        );
        assert_no_symbol_or_schema_overlaps("migration_keyword_docs", &analysis);
    }

    #[test]
    fn analyze_workspace_pair_independent_import_churn_stays_at_or_below_yellow() {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");
        init_repo_with_main(&repo);

        let gap = "\n".repeat(140);
        let base_source = format!(
            "use std::collections::HashMap;\n\npub fn top() -> usize {{\n    1\n}}\n{gap}use std::collections::HashSet;\n\npub fn bottom() -> usize {{\n    2\n}}\n"
        );
        write_file(&repo.join("src/lib.rs"), &base_source);
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        run_git(&repo, &["checkout", "-b", "feat/a"]);
        let a_source = format!(
            "use std::collections::BTreeMap;\n\npub fn top() -> usize {{\n    1\n}}\n{gap}use std::collections::HashSet;\n\npub fn bottom() -> usize {{\n    2\n}}\n"
        );
        write_file(&repo.join("src/lib.rs"), &a_source);
        run_git(&repo, &["commit", "-am", "feat a import"]);

        let wt_b = add_worktree_from_main(&repo, temp.path(), "wt-b-import", "feat/b-import");
        let b_source = format!(
            "use std::collections::HashMap;\n\npub fn top() -> usize {{\n    1\n}}\n{gap}use std::collections::VecDeque;\n\npub fn bottom() -> usize {{\n    2\n}}\n"
        );
        write_file(&wt_b.join("src/lib.rs"), &b_source);
        run_git(&wt_b, &["commit", "-am", "feat b import"]);

        let ws_a = make_workspace(repo.clone(), "feat/a");
        let ws_b = make_workspace(wt_b.clone(), "feat/b-import");
        let analysis = analyze_workspace_pair(&default_config(), &ws_a, &ws_b, &ImportGraph::new())
            .expect("analysis should succeed");

        assert_score_at_most_yellow("independent_import_churn", &analysis);
        assert_no_symbol_or_schema_overlaps("independent_import_churn", &analysis);
    }

    #[test]
    fn extract_changeset_includes_uncommitted_changes() {
        // Setup: temp repo with initial commit on main, then a branch with
        // an uncommitted file change — extract_changeset should see it.
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");

        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "grove@example.com"]);
        run_git(&repo, &["config", "user.name", "Grove Tests"]);

        write_file(
            &repo.join("src/lib.rs"),
            "pub fn hello() -> &'static str {\n    \"hello\"\n}\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        // Create branch but do NOT commit the change — only write to disk.
        run_git(&repo, &["checkout", "-b", "feat/dirty"]);
        write_file(
            &repo.join("src/lib.rs"),
            "pub fn hello() -> &'static str {\n    \"world\"\n}\n",
        );

        let ws = make_workspace(repo.clone(), "feat/dirty");
        let config = GroveConfig {
            base_branch: "main".to_string(),
            ..GroveConfig::default()
        };

        let registry = LanguageRegistry::with_defaults();
        let changeset = extract_changeset(&config, &registry, &ws).expect("extract should succeed");

        // The uncommitted file should appear in changed_files.
        assert!(
            changeset
                .changed_files
                .iter()
                .any(|f| f.path == PathBuf::from("src/lib.rs")),
            "uncommitted dirty file should appear in changeset"
        );

        // The hunks should reflect the working-tree diff (\"hello\" -> \"world\").
        let file = changeset
            .changed_files
            .iter()
            .find(|f| f.path == PathBuf::from("src/lib.rs"))
            .expect("src/lib.rs should be in changeset");
        assert!(!file.hunks.is_empty(), "dirty file should have diff hunks");
    }

    #[test]
    fn extract_changeset_merges_committed_and_uncommitted_changes() {
        // A file that has both committed changes (merge-base to HEAD) AND further
        // uncommitted edits should show the full diff from merge-base to working-tree.
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");

        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "grove@example.com"]);
        run_git(&repo, &["config", "user.name", "Grove Tests"]);

        write_file(
            &repo.join("src/lib.rs"),
            "fn one() {}\nfn two() {}\nfn three() {}\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        // Committed change on branch: modify line 1
        run_git(&repo, &["checkout", "-b", "feat/combo"]);
        write_file(
            &repo.join("src/lib.rs"),
            "fn one_modified() {}\nfn two() {}\nfn three() {}\n",
        );
        run_git(&repo, &["commit", "-am", "modify one"]);

        // Further uncommitted change: also modify line 3
        write_file(
            &repo.join("src/lib.rs"),
            "fn one_modified() {}\nfn two() {}\nfn three_modified() {}\n",
        );

        let ws = make_workspace(repo.clone(), "feat/combo");
        let config = GroveConfig {
            base_branch: "main".to_string(),
            ..GroveConfig::default()
        };

        let registry = LanguageRegistry::with_defaults();
        let changeset = extract_changeset(&config, &registry, &ws).expect("extract should succeed");

        let file = changeset
            .changed_files
            .iter()
            .find(|f| f.path == PathBuf::from("src/lib.rs"))
            .expect("src/lib.rs should be in changeset");

        // Should see hunks covering both changes (line 1 and line 3).
        assert!(
            file.hunks.len() >= 2,
            "should have hunks for both committed and uncommitted changes, got {}",
            file.hunks.len()
        );
    }

    #[test]
    fn build_base_graph_from_workspace_resolves_relative_imports() {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");

        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "grove@example.com"]);
        run_git(&repo, &["config", "user.name", "Grove Tests"]);

        write_file(
            &repo.join("src/shared.ts"),
            "export function authenticate(token: string): boolean { return token.length > 0; }\n",
        );
        write_file(
            &repo.join("src/api.ts"),
            "import { authenticate } from \"./shared\";\nexport function checkout(token: string): boolean { return authenticate(token); }\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        let ws = make_workspace(repo.clone(), "main");
        let config = GroveConfig {
            base_branch: "main".to_string(),
            ..GroveConfig::default()
        };

        let (graph, base_commit) =
            build_base_graph_from_workspace(&config, &ws).expect("base graph build should pass");

        assert!(
            !base_commit.is_empty(),
            "base commit should be resolved when graph builds"
        );
        assert!(
            graph
                .get_dependents(&PathBuf::from("src/shared.ts"))
                .contains(&&PathBuf::from("src/api.ts")),
            "shared.ts should have api.ts as a dependent"
        );
    }
}
