use crate::state::{GroveConfig, StateMessage};
use chrono::Utc;
use grove_lib::graph::{ImportGraph, compute_dependency_overlaps};
use grove_lib::languages::LanguageRegistry;
use grove_lib::scorer;
use grove_lib::{
    ChangeType, ExportDelta, ExportedSymbol, FileChange, Hunk, LineRange, Signature, Symbol,
    Workspace, WorkspaceChangeset, WorkspacePairAnalysis,
};
use std::collections::{BTreeMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, warn};

#[derive(Debug, Clone)]
pub enum WorkerMessage {
    AnalyzePair {
        workspace_a: Workspace,
        workspace_b: Workspace,
        base_graph: ImportGraph,
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
                    }
                    Err(e) => {
                        error!(
                            workspace_a = %a_id,
                            workspace_b = %b_id,
                            error = %e,
                            "worker task panicked"
                        );
                    }
                },
                Err(_) => {
                    warn!(
                        workspace_a = %a_id,
                        workspace_b = %b_id,
                        timeout_ms,
                        "pair analysis timed out"
                    );
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
    let changes_a = extract_changeset(config, workspace_a)?;
    let changes_b = extract_changeset(config, workspace_b)?;

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
    let base_ref = if workspace.base_ref.is_empty() {
        config.base_branch.as_str()
    } else {
        workspace.base_ref.as_str()
    };

    let base_commit = git_output_line(
        &workspace.path,
        ["rev-parse", base_ref],
        "rev-parse base ref",
    )?;

    let files_output = git_output(
        &workspace.path,
        ["ls-tree", "-r", "--name-only", base_ref],
        "ls-tree base branch",
    )?;

    let file_paths: Vec<PathBuf> = files_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    let file_set: HashSet<PathBuf> = file_paths.iter().cloned().collect();

    let registry = LanguageRegistry::with_defaults();
    let mut graph = ImportGraph::new();
    let max_file_size_bytes = config.max_file_size_kb.saturating_mul(1024);

    for file_path in file_paths {
        let Some(analyzer) = registry.analyzer_for_file(file_path.as_path()) else {
            continue;
        };

        let show_spec = format!("{base_ref}:{}", file_path.to_string_lossy());
        let content = match git_output_bytes(
            &workspace.path,
            ["show", show_spec.as_str()],
            "show base file",
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                debug!(
                    path = %file_path.display(),
                    error = %err,
                    "skipping file while building base graph"
                );
                continue;
            }
        };

        if content.len() as u64 > max_file_size_bytes {
            debug!(
                path = %file_path.display(),
                size = content.len(),
                max = max_file_size_bytes,
                "skipping oversized file while building base graph"
            );
            continue;
        }

        let exports = analyzer.extract_exports(&content).unwrap_or_default();
        graph.set_exports(file_path.clone(), exports);

        let imports = analyzer.extract_imports(&content).unwrap_or_default();
        for import in imports {
            if let Some(target_path) = resolve_import_target(
                file_path.as_path(),
                &import.source,
                &file_set,
                analyzer.file_extensions(),
            ) {
                graph.add_import(file_path.clone(), target_path, import.symbols);
            }
        }
    }

    Ok((graph, base_commit))
}

fn resolve_import_target(
    importer: &Path,
    source: &str,
    file_set: &HashSet<PathBuf>,
    importer_extensions: &[&str],
) -> Option<PathBuf> {
    if source.is_empty() {
        return None;
    }

    // Dependency overlap tracking is currently path-based; resolve local imports.
    if !source.starts_with("./") && !source.starts_with("../") {
        return None;
    }

    let importer_dir = importer.parent().unwrap_or(Path::new(""));
    let base_candidate = normalize_relative_path(importer_dir.join(source));

    if file_set.contains(&base_candidate) {
        return Some(base_candidate);
    }

    if base_candidate.extension().is_some() {
        return None;
    }

    for ext in importer_extensions {
        let with_extension = base_candidate.with_extension(ext);
        if file_set.contains(&with_extension) {
            return Some(with_extension);
        }
    }

    for ext in importer_extensions {
        let index_path = base_candidate.join(format!("index.{ext}"));
        if file_set.contains(&index_path) {
            return Some(index_path);
        }
    }

    None
}

fn normalize_relative_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::RootDir | Component::Prefix(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }

    normalized
}

fn extract_changeset(
    config: &GroveConfig,
    workspace: &Workspace,
) -> Result<WorkspaceChangeset, WorkerError> {
    use crate::git::{GitRepo, compute_hunks_from_content};

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

    let mut files = Vec::new();
    let registry = LanguageRegistry::with_defaults();
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

        // Phase 2C: compute hunks in-process from content (was git diff --unified=0 subprocess)
        let hunks = compute_hunks_from_content(old_content.as_deref(), new_content.as_deref());

        let symbols_modified = extract_modified_symbols(
            &registry,
            new_path,
            new_content.as_deref(),
            &hunks,
            status.change_type,
            max_file_size_bytes,
        );

        let old_exports = extract_exports(
            &registry,
            old_path,
            old_content.as_deref(),
            max_file_size_bytes,
        );
        let new_exports = extract_exports(
            &registry,
            new_path,
            new_content.as_deref(),
            max_file_size_bytes,
        );
        let exports_changed = compute_export_deltas(&old_exports, &new_exports);

        files.push(FileChange {
            path: status.path,
            change_type: status.change_type,
            hunks,
            symbols_modified,
            exports_changed,
        });
    }

    Ok(WorkspaceChangeset {
        workspace_id: workspace.id,
        merge_base,
        changed_files: files,
        commits_ahead: ahead_behind.1,
        commits_behind: ahead_behind.0,
    })
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

fn extract_modified_symbols(
    registry: &LanguageRegistry,
    path: &Path,
    content: Option<&[u8]>,
    hunks: &[Hunk],
    change_type: ChangeType,
    max_file_size_bytes: u64,
) -> Vec<Symbol> {
    let Some(bytes) = content else {
        return Vec::new();
    };

    if bytes.len() as u64 > max_file_size_bytes {
        debug!(
            path = %path.display(),
            size = bytes.len(),
            max = max_file_size_bytes,
            "skipping symbol extraction for large file"
        );
        return Vec::new();
    }

    let Some(analyzer) = registry.analyzer_for_file(path) else {
        return Vec::new();
    };

    let symbols = match analyzer.extract_symbols(bytes) {
        Ok(symbols) => symbols,
        Err(e) => {
            debug!(path = %path.display(), error = %e, "symbol extraction failed");
            return Vec::new();
        }
    };

    match change_type {
        ChangeType::Added => symbols,
        ChangeType::Deleted => Vec::new(),
        ChangeType::Modified | ChangeType::Renamed => {
            if hunks.is_empty() {
                return Vec::new();
            }

            symbols
                .into_iter()
                .filter(|symbol| symbol_in_hunks(symbol, hunks))
                .collect()
        }
    }
}

fn symbol_in_hunks(symbol: &Symbol, hunks: &[Hunk]) -> bool {
    hunks.iter().any(|hunk| {
        let start = hunk.new_start;
        let end = if hunk.new_lines == 0 {
            hunk.new_start
        } else {
            hunk.new_start + hunk.new_lines.saturating_sub(1)
        };
        symbol.range.overlaps(&LineRange { start, end })
    })
}

fn extract_exports(
    registry: &LanguageRegistry,
    path: &Path,
    content: Option<&[u8]>,
    max_file_size_bytes: u64,
) -> Vec<ExportedSymbol> {
    let Some(bytes) = content else {
        return Vec::new();
    };

    if bytes.len() as u64 > max_file_size_bytes {
        return Vec::new();
    }

    let Some(analyzer) = registry.analyzer_for_file(path) else {
        return Vec::new();
    };

    analyzer.extract_exports(bytes).unwrap_or_default()
}

fn compute_export_deltas(
    old_exports: &[ExportedSymbol],
    new_exports: &[ExportedSymbol],
) -> Vec<ExportDelta> {
    let old_by_name: BTreeMap<&str, &ExportedSymbol> = old_exports
        .iter()
        .map(|exported| (exported.name.as_str(), exported))
        .collect();
    let new_by_name: BTreeMap<&str, &ExportedSymbol> = new_exports
        .iter()
        .map(|exported| (exported.name.as_str(), exported))
        .collect();

    let mut deltas = Vec::new();

    for (name, new_symbol) in &new_by_name {
        if let Some(old_symbol) = old_by_name.get(name) {
            if old_symbol.signature != new_symbol.signature || old_symbol.kind != new_symbol.kind {
                deltas.push(ExportDelta::SignatureChanged {
                    symbol_name: (*name).to_string(),
                    old: Signature {
                        text: signature_text(old_symbol),
                    },
                    new: Signature {
                        text: signature_text(new_symbol),
                    },
                });
            }
        } else {
            deltas.push(ExportDelta::Added(exported_to_symbol(new_symbol)));
        }
    }

    for (name, old_symbol) in &old_by_name {
        if !new_by_name.contains_key(name) {
            deltas.push(ExportDelta::Removed(exported_to_symbol(old_symbol)));
        }
    }

    deltas
}

fn signature_text(exported: &ExportedSymbol) -> String {
    exported
        .signature
        .clone()
        .unwrap_or_else(|| format!("{:?}:{}", exported.kind, exported.name))
}

fn exported_to_symbol(exported: &ExportedSymbol) -> Symbol {
    Symbol {
        name: exported.name.clone(),
        kind: exported.kind,
        range: LineRange { start: 0, end: 0 },
        signature: exported.signature.clone(),
    }
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

        let changeset = extract_changeset(&config, &ws).expect("extract should succeed");

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

        let changeset = extract_changeset(&config, &ws).expect("extract should succeed");

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
