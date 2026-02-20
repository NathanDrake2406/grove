use crate::state::{GroveConfig, StateMessage};
use chrono::Utc;
use grove_lib::graph::{ImportGraph, compute_dependency_overlaps};
use grove_lib::languages::LanguageRegistry;
use grove_lib::scorer;
use grove_lib::{
    ChangeType, ExportDelta, ExportedSymbol, FileChange, Hunk, LineRange, OrthogonalityScore,
    Signature, Symbol, Workspace, WorkspaceChangeset, WorkspacePairAnalysis,
};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
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
        .max(1)
        .min(8);

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

        while in_flight.join_next().await.is_some() {}
        info!("worker pool stopped");
    });

    WorkerPool { tx, handle }
}

async fn process_message(msg: WorkerMessage, config: GroveConfig, state_tx: mpsc::Sender<StateMessage>) {
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

            let result = timeout(timeout_duration, tokio::task::spawn_blocking(move || {
                analyze_workspace_pair(&analysis_config, &workspace_a, &workspace_b, &base_graph)
            }))
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

fn extract_changeset(config: &GroveConfig, workspace: &Workspace) -> Result<WorkspaceChangeset, WorkerError> {
    let base_ref = if workspace.base_ref.is_empty() {
        config.base_branch.as_str()
    } else {
        workspace.base_ref.as_str()
    };

    let merge_base = git_output_line(
        &workspace.path,
        ["merge-base", "HEAD", base_ref],
        "merge-base",
    )?;

    let ahead_behind = git_output_line(
        &workspace.path,
        ["rev-list", "--left-right", "--count", &format!("{base_ref}...HEAD")],
        "rev-list --left-right --count",
    )
    .ok()
    .and_then(|line| parse_left_right_counts(&line))
    .unwrap_or((0, 0));

    let status_output = git_output(
        &workspace.path,
        [
            "diff",
            "--name-status",
            "--find-renames",
            "--no-color",
            &format!("{merge_base}..HEAD"),
        ],
        "diff --name-status",
    )?;
    let statuses = parse_name_status_output(&status_output);

    let patch_output = git_output(
        &workspace.path,
        [
            "diff",
            "--unified=0",
            "--find-renames",
            "--no-color",
            &format!("{merge_base}..HEAD"),
        ],
        "diff --unified=0",
    )?;
    let hunks_by_path = parse_unified_diff_hunks(&patch_output);

    let mut files = Vec::new();
    let registry = LanguageRegistry::with_defaults();
    let max_file_size_bytes = config.max_file_size_kb * 1024;

    for status in statuses {
        let hunks = hunks_by_path.get(&status.path).cloned().unwrap_or_default();
        let old_path = status.old_path.as_deref().unwrap_or(status.path.as_path());
        let new_path = status.path.as_path();

        let old_content = match status.change_type {
            ChangeType::Added => None,
            ChangeType::Modified | ChangeType::Deleted | ChangeType::Renamed => {
                git_show_file(&workspace.path, &merge_base, old_path)
            }
        };

        let new_content = match status.change_type {
            ChangeType::Deleted => None,
            ChangeType::Added | ChangeType::Modified | ChangeType::Renamed => {
                git_show_file(&workspace.path, "HEAD", new_path)
            }
        };

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
struct DiffFileStatus {
    path: PathBuf,
    old_path: Option<PathBuf>,
    change_type: ChangeType,
}

fn parse_name_status_output(output: &str) -> Vec<DiffFileStatus> {
    let mut parsed = Vec::new();

    for line in output.lines() {
        let mut parts = line.split('\t');
        let Some(status) = parts.next() else {
            continue;
        };

        if status.starts_with('R') {
            let Some(old_path) = parts.next() else {
                continue;
            };
            let Some(new_path) = parts.next() else {
                continue;
            };
            parsed.push(DiffFileStatus {
                path: PathBuf::from(new_path),
                old_path: Some(PathBuf::from(old_path)),
                change_type: ChangeType::Renamed,
            });
            continue;
        }

        let Some(path) = parts.next() else {
            continue;
        };

        let change_type = match status.chars().next() {
            Some('A') => ChangeType::Added,
            Some('D') => ChangeType::Deleted,
            Some('M') => ChangeType::Modified,
            _ => ChangeType::Modified,
        };

        parsed.push(DiffFileStatus {
            path: PathBuf::from(path),
            old_path: None,
            change_type,
        });
    }

    parsed
}

fn parse_unified_diff_hunks(output: &str) -> HashMap<PathBuf, Vec<Hunk>> {
    let mut hunks_by_path: HashMap<PathBuf, Vec<Hunk>> = HashMap::new();
    let mut current_path: Option<PathBuf> = None;

    for line in output.lines() {
        if let Some((old_path, new_path)) = parse_diff_header_paths(line) {
            current_path = if new_path == PathBuf::from("/dev/null") {
                Some(old_path)
            } else {
                Some(new_path)
            };
            continue;
        }

        if let Some(hunk) = parse_hunk_header(line)
            && let Some(path) = current_path.clone()
        {
            hunks_by_path.entry(path).or_default().push(hunk);
        }
    }

    hunks_by_path
}

fn parse_diff_header_paths(line: &str) -> Option<(PathBuf, PathBuf)> {
    if !line.starts_with("diff --git ") {
        return None;
    }

    let mut tokens = line.split_whitespace();
    let _ = tokens.next()?; // diff
    let _ = tokens.next()?; // --git
    let old = tokens.next()?;
    let new = tokens.next()?;

    Some((PathBuf::from(strip_diff_prefix(old)), PathBuf::from(strip_diff_prefix(new))))
}

fn strip_diff_prefix(value: &str) -> &str {
    value
        .strip_prefix("a/")
        .or_else(|| value.strip_prefix("b/"))
        .unwrap_or(value)
}

fn parse_hunk_header(line: &str) -> Option<Hunk> {
    if !line.starts_with("@@ -") {
        return None;
    }

    let without_prefix = line.strip_prefix("@@ -")?;
    let (ranges, _) = without_prefix.split_once(" @@")?;
    let (old_range, new_range) = ranges.split_once(" +")?;
    let (old_start, old_lines) = parse_diff_range(old_range)?;
    let (new_start, new_lines) = parse_diff_range(new_range)?;

    Some(Hunk {
        old_start,
        old_lines,
        new_start,
        new_lines,
    })
}

fn parse_diff_range(range: &str) -> Option<(u32, u32)> {
    let mut parts = range.split(',');
    let start = parts.next()?.parse::<u32>().ok()?;
    let lines = parts
        .next()
        .map(|v| v.parse::<u32>().ok())
        .unwrap_or(Some(1))?;
    Some((start, lines))
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

fn compute_export_deltas(old_exports: &[ExportedSymbol], new_exports: &[ExportedSymbol]) -> Vec<ExportDelta> {
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

fn git_show_file(repo_path: &Path, revision: &str, path: &Path) -> Option<Vec<u8>> {
    let spec = format!("{}:{}", revision, path.to_string_lossy());
    let output = Command::new("git")
        .current_dir(repo_path)
        .args(["show", spec.as_str()])
        .output()
        .ok()?;

    if output.status.success() {
        Some(output.stdout)
    } else {
        None
    }
}

fn git_output_line<const N: usize>(
    repo_path: &Path,
    args: [&str; N],
    context: &'static str,
) -> Result<String, WorkerError> {
    let output = git_output(repo_path, args, context)?;
    Ok(output.lines().next().unwrap_or_default().trim().to_string())
}

fn git_output<const N: usize>(
    repo_path: &Path,
    args: [&str; N],
    context: &'static str,
) -> Result<String, WorkerError> {
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

    String::from_utf8(output.stdout).map_err(|source| WorkerError::InvalidUtf8 {
        context,
        repo_path: repo_path.to_path_buf(),
        source,
    })
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
    use grove_lib::{MergeOrder, WorkspaceMetadata};
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

    #[test]
    fn parses_name_status_with_rename() {
        let output = "M\tsrc/lib.rs\nA\tsrc/new.rs\nD\tsrc/old.rs\nR100\tsrc/from.rs\tsrc/to.rs\n";
        let statuses = parse_name_status_output(output);

        assert_eq!(statuses.len(), 4);
        assert_eq!(statuses[0].change_type, ChangeType::Modified);
        assert_eq!(statuses[1].change_type, ChangeType::Added);
        assert_eq!(statuses[2].change_type, ChangeType::Deleted);
        assert_eq!(statuses[3].change_type, ChangeType::Renamed);
        assert_eq!(statuses[3].old_path, Some(PathBuf::from("src/from.rs")));
        assert_eq!(statuses[3].path, PathBuf::from("src/to.rs"));
    }

    #[test]
    fn parses_unified_diff_hunks() {
        let diff = "diff --git a/src/lib.rs b/src/lib.rs\n@@ -1,2 +1,3 @@\n+line\ndiff --git a/src/old.rs b/src/old.rs\n@@ -10 +10,0 @@\n-line\n";

        let hunks = parse_unified_diff_hunks(diff);
        assert_eq!(hunks.len(), 2);

        let first = hunks
            .get(&PathBuf::from("src/lib.rs"))
            .expect("first file hunks should exist");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].old_start, 1);
        assert_eq!(first[0].old_lines, 2);
        assert_eq!(first[0].new_start, 1);
        assert_eq!(first[0].new_lines, 3);

        let second = hunks
            .get(&PathBuf::from("src/old.rs"))
            .expect("second file hunks should exist");
        assert_eq!(second[0].new_lines, 0);
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
            MergeOrder::AFirst | MergeOrder::BFirst | MergeOrder::NeedsCoordination | MergeOrder::Either
        ));
    }
}
