use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use grove_lib::changeset::{ContentChange, build_workspace_changeset};
use grove_lib::diff::{compute_file_overlaps, compute_hunk_overlaps};
use grove_lib::fs::GitObjectFileSystem;
use grove_lib::graph::{ImportGraph, build_import_graph_from_paths, compute_dependency_overlaps};
use grove_lib::languages::LanguageRegistry;
use grove_lib::merge_order::compute_merge_order;
use grove_lib::schema::compute_schema_overlaps;
use grove_lib::scorer::{build_pair_analysis, compute_symbol_overlaps};
use grove_lib::{
    ChangeType, ExportDelta, Location, OrthogonalityScore, Overlap, SchemaCategory,
    WorkspaceChangeset, WorkspaceId,
};
use serde::Serialize;
use uuid::Uuid;

use crate::commands::CommandError;

#[derive(clap::Subcommand, Debug, Clone)]
pub enum CiAction {
    /// Analyze multiple refs for cross-branch conflicts
    Analyze(AnalyzeArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct AnalyzeArgs {
    /// Base branch to diff against
    #[arg(long, default_value = "main")]
    pub base: String,

    /// Read ref specs from stdin, one per line
    #[arg(long)]
    pub refs_from_stdin: bool,

    /// Per-pair timeout in seconds
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// Disable a specific analysis layer
    #[arg(long, value_enum)]
    pub disable_layer: Vec<AnalysisLayer>,

    /// Ref specs to analyze
    #[arg(value_name = "REF")]
    pub refs: Vec<String>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalysisLayer {
    File,
    Hunk,
    Symbol,
    Dependency,
    Schema,
}

pub async fn execute(args: &AnalyzeArgs) -> Result<(), CommandError> {
    let repo = GitRepo::open(&std::env::current_dir()?)?;
    let ref_specs = load_ref_specs(args)?;
    let output = analyze_repository(&repo, args, ref_specs)?;

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn analyze_repository(
    repo: &GitRepo,
    args: &AnalyzeArgs,
    ref_specs: Vec<RefSpec>,
) -> Result<CiAnalyzeOutput, CommandError> {
    let base_oid = repo.resolve_oid(&args.base).map_err(|error| {
        CommandError::InvalidInput(format!(
            "failed to resolve base ref `{}`: {error}",
            args.base
        ))
    })?;
    let disabled_layers: HashSet<AnalysisLayer> = args.disable_layer.iter().copied().collect();
    let namespace = repo.workspace_namespace();
    let registry = LanguageRegistry::with_defaults();

    let base_graph = if disabled_layers.contains(&AnalysisLayer::Dependency) {
        ImportGraph::new()
    } else {
        build_base_graph(repo, &args.base)?
    };
    let base_graph = Arc::new(base_graph);

    let mut skipped = Vec::new();
    let mut targets = Vec::new();
    for ref_spec in ref_specs {
        match prepare_target(repo, &registry, base_oid, &args.base, namespace, ref_spec)? {
            PreparedTarget::Ready(target) => targets.push(target),
            PreparedTarget::Skipped(entry) => skipped.push(entry),
        }
    }

    let label_by_id: HashMap<WorkspaceId, String> = targets
        .iter()
        .map(|target| (target.workspace_id, target.label.clone()))
        .collect();

    let mut pair_outputs = Vec::new();
    let mut successful_analyses = Vec::new();
    let mut incomplete_pairs = Vec::new();

    for index_a in 0..targets.len() {
        for index_b in (index_a + 1)..targets.len() {
            let left = &targets[index_a];
            let right = &targets[index_b];

            let execution = if should_force_timeout(&left.ref_name, &right.ref_name) {
                PairExecution::TimedOut
            } else {
                analyze_pair_with_timeout(
                    left.changeset.clone(),
                    right.changeset.clone(),
                    base_graph.clone(),
                    disabled_layers.clone(),
                    Duration::from_secs(args.timeout),
                )
            };

            match execution {
                PairExecution::Completed(analysis) => {
                    pair_outputs.push(CiPairDto::from_analysis(&analysis, &label_by_id)?);
                    successful_analyses.push(analysis);
                }
                PairExecution::TimedOut => {
                    pair_outputs.push(CiPairDto::timed_out(
                        left.label.clone(),
                        right.label.clone(),
                    ));
                    incomplete_pairs.push(CiIncompletePairDto {
                        a: left.label.clone(),
                        b: right.label.clone(),
                    });
                }
            }
        }
    }

    let merge_order = build_merge_order_output(&targets, &successful_analyses, &incomplete_pairs);

    Ok(CiAnalyzeOutput {
        base: args.base.clone(),
        refs: targets
            .into_iter()
            .map(|target| CiRefDto {
                r#ref: target.ref_name,
                label: target.label,
            })
            .collect(),
        pairs: pair_outputs,
        merge_order,
        skipped,
    })
}

fn load_ref_specs(args: &AnalyzeArgs) -> Result<Vec<RefSpec>, CommandError> {
    if args.refs_from_stdin && !args.refs.is_empty() {
        return Err(CommandError::InvalidInput(
            "pass refs either via stdin or positional args, not both".to_string(),
        ));
    }
    if !args.refs_from_stdin && args.refs.is_empty() {
        return Err(CommandError::InvalidInput(
            "provide at least one ref or use --refs-from-stdin".to_string(),
        ));
    }

    let raw_specs = if args.refs_from_stdin {
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    } else {
        args.refs.clone()
    };

    if raw_specs.is_empty() {
        return Err(CommandError::InvalidInput(
            "provide at least one non-empty ref".to_string(),
        ));
    }

    let mut seen_refs = HashSet::new();
    let mut ref_specs = Vec::with_capacity(raw_specs.len());
    for raw in raw_specs {
        let ref_spec = RefSpec::parse(&raw)?;
        if !seen_refs.insert(ref_spec.ref_name.clone()) {
            return Err(CommandError::InvalidInput(format!(
                "duplicate ref `{}`",
                ref_spec.ref_name
            )));
        }
        ref_specs.push(ref_spec);
    }

    Ok(ref_specs)
}

fn build_base_graph(repo: &GitRepo, base_ref: &str) -> Result<ImportGraph, CommandError> {
    let base_tree = repo.resolve_tree(base_ref).map_err(|error| {
        CommandError::InvalidInput(format!(
            "failed to resolve base tree for `{base_ref}`: {error}"
        ))
    })?;
    let records = base_tree.traverse().breadthfirst.files().map_err(|error| {
        CommandError::AnalysisError(format!("failed to traverse base tree: {error}"))
    })?;
    let file_paths: Vec<PathBuf> = records
        .into_iter()
        .filter(|entry| !entry.mode.is_tree())
        .map(|entry| PathBuf::from(entry.filepath.to_string()))
        .collect();

    let file_system = GitObjectFileSystem::open(repo.root(), base_ref).map_err(|error| {
        CommandError::AnalysisError(format!(
            "failed to open git object filesystem for `{base_ref}`: {error}"
        ))
    })?;
    let registry = LanguageRegistry::with_defaults();

    Ok(build_import_graph_from_paths(
        &file_system,
        &registry,
        &file_paths,
        MAX_FILE_SIZE_BYTES,
    ))
}

fn prepare_target(
    repo: &GitRepo,
    registry: &LanguageRegistry,
    base_oid: gix::ObjectId,
    base_ref: &str,
    namespace: Uuid,
    ref_spec: RefSpec,
) -> Result<PreparedTarget, CommandError> {
    let ref_oid = match repo.resolve_oid(&ref_spec.ref_name) {
        Ok(oid) => oid,
        Err(_) => {
            return Ok(PreparedTarget::Skipped(CiSkippedRefDto {
                r#ref: ref_spec.ref_name,
                label: ref_spec.label,
                reason: "ref not found".to_string(),
            }));
        }
    };

    let merge_base = repo.merge_base(base_oid, ref_oid).map_err(|error| {
        CommandError::AnalysisError(format!(
            "failed to compute merge base for `{}` against `{base_ref}`: {error}",
            ref_spec.ref_name
        ))
    })?;
    if merge_base == ref_oid {
        return Ok(PreparedTarget::Skipped(CiSkippedRefDto {
            r#ref: ref_spec.ref_name,
            label: ref_spec.label,
            reason: "no diff against base".to_string(),
        }));
    }

    let changeset = build_changeset_for_ref(
        repo,
        registry,
        namespace,
        base_oid,
        ref_oid,
        &ref_spec.ref_name,
    )?;

    if changeset.changed_files.is_empty() {
        return Ok(PreparedTarget::Skipped(CiSkippedRefDto {
            r#ref: ref_spec.ref_name,
            label: ref_spec.label,
            reason: "no diff against base".to_string(),
        }));
    }

    Ok(PreparedTarget::Ready(AnalysisTarget {
        ref_name: ref_spec.ref_name,
        label: ref_spec.label,
        workspace_id: changeset.workspace_id,
        changeset: Arc::new(changeset),
    }))
}

fn build_changeset_for_ref(
    repo: &GitRepo,
    registry: &LanguageRegistry,
    namespace: Uuid,
    base_oid: gix::ObjectId,
    ref_oid: gix::ObjectId,
    ref_name: &str,
) -> Result<WorkspaceChangeset, CommandError> {
    let merge_base = repo.merge_base(base_oid, ref_oid).map_err(|error| {
        CommandError::AnalysisError(format!(
            "failed to compute merge base for `{ref_name}`: {error}"
        ))
    })?;
    let merge_base_hex = merge_base.to_hex().to_string();
    let counts = repo.count_left_right(base_oid, ref_oid)?;

    let base_tree = repo.tree_from_oid(merge_base).map_err(|error| {
        CommandError::AnalysisError(format!(
            "failed to resolve merge-base tree for `{ref_name}`: {error}"
        ))
    })?;
    let ref_tree = repo.tree_from_oid(ref_oid).map_err(|error| {
        CommandError::AnalysisError(format!("failed to resolve tree for `{ref_name}`: {error}"))
    })?;
    let statuses = repo
        .diff_name_status(&base_tree, &ref_tree)
        .map_err(|error| {
            CommandError::AnalysisError(format!(
                "failed to diff `{ref_name}` against merge base: {error}"
            ))
        })?;

    let mut base_tree_mut = repo.tree_from_oid(merge_base).map_err(|error| {
        CommandError::AnalysisError(format!(
            "failed to resolve merge-base tree for blob reads in `{ref_name}`: {error}"
        ))
    })?;
    let mut ref_tree_mut = repo.tree_from_oid(ref_oid).map_err(|error| {
        CommandError::AnalysisError(format!(
            "failed to resolve tree for blob reads in `{ref_name}`: {error}"
        ))
    })?;

    let mut changes = Vec::with_capacity(statuses.len());
    for status in statuses {
        let old_path = status.old_path.as_deref().unwrap_or(status.path.as_path());
        let new_path = status.path.as_path();

        let old_content = match status.change_type {
            ChangeType::Added => None,
            ChangeType::Modified | ChangeType::Deleted | ChangeType::Renamed => {
                repo.read_blob(&mut base_tree_mut, old_path)
            }
        };
        let new_content = match status.change_type {
            ChangeType::Deleted => None,
            ChangeType::Added | ChangeType::Modified | ChangeType::Renamed => {
                repo.read_blob(&mut ref_tree_mut, new_path)
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

    let workspace_id = Uuid::new_v5(&namespace, ref_name.as_bytes());
    Ok(build_workspace_changeset(
        registry,
        workspace_id,
        merge_base_hex,
        counts.1,
        counts.0,
        changes,
        MAX_FILE_SIZE_BYTES,
    ))
}

fn analyze_pair_with_timeout(
    changes_a: Arc<WorkspaceChangeset>,
    changes_b: Arc<WorkspaceChangeset>,
    base_graph: Arc<ImportGraph>,
    disabled_layers: HashSet<AnalysisLayer>,
    timeout_duration: Duration,
) -> PairExecution {
    if timeout_duration.is_zero() {
        return PairExecution::TimedOut;
    }

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let analysis = analyze_pair(
            changes_a.as_ref(),
            changes_b.as_ref(),
            base_graph.as_ref(),
            &disabled_layers,
        );
        let _ = sender.send(analysis);
    });

    match receiver.recv_timeout(timeout_duration) {
        Ok(analysis) => PairExecution::Completed(analysis),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => PairExecution::TimedOut,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => PairExecution::TimedOut,
    }
}

fn analyze_pair(
    changes_a: &WorkspaceChangeset,
    changes_b: &WorkspaceChangeset,
    base_graph: &ImportGraph,
    disabled_layers: &HashSet<AnalysisLayer>,
) -> grove_lib::WorkspacePairAnalysis {
    let mut overlaps = Vec::new();

    if !disabled_layers.contains(&AnalysisLayer::File) {
        overlaps.extend(compute_file_overlaps(changes_a, changes_b));
    }
    if !disabled_layers.contains(&AnalysisLayer::Hunk) {
        overlaps.extend(compute_hunk_overlaps(
            changes_a,
            changes_b,
            HUNK_PROXIMITY_THRESHOLD,
        ));
    }
    if !disabled_layers.contains(&AnalysisLayer::Symbol) {
        overlaps.extend(compute_symbol_overlaps(changes_a, changes_b));
    }
    if !disabled_layers.contains(&AnalysisLayer::Schema) {
        overlaps.extend(compute_schema_overlaps(changes_a, changes_b));
    }
    if !disabled_layers.contains(&AnalysisLayer::Dependency) {
        overlaps.extend(compute_dependency_overlaps(
            changes_a, changes_b, base_graph,
        ));
    }

    build_pair_analysis(changes_a, changes_b, overlaps, Utc::now())
}

fn build_merge_order_output(
    targets: &[AnalysisTarget],
    successful_analyses: &[grove_lib::WorkspacePairAnalysis],
    incomplete_pairs: &[CiIncompletePairDto],
) -> CiMergeOrderDto {
    let workspace_ids: Vec<WorkspaceId> =
        targets.iter().map(|target| target.workspace_id).collect();
    let merge_sequence = compute_merge_order(successful_analyses, &workspace_ids);
    let label_by_id: HashMap<WorkspaceId, String> = targets
        .iter()
        .map(|target| (target.workspace_id, target.label.clone()))
        .collect();

    let status = if !incomplete_pairs.is_empty()
        && successful_analyses.is_empty()
        && workspace_ids.len() > 1
    {
        MergeOrderStatus::Unavailable
    } else if !incomplete_pairs.is_empty() {
        MergeOrderStatus::Partial
    } else if merge_sequence.has_cycle {
        MergeOrderStatus::Cycle
    } else {
        MergeOrderStatus::Complete
    };

    CiMergeOrderDto {
        status,
        sequenced: merge_sequence
            .ordered
            .iter()
            .map(|workspace_id| label_by_id[workspace_id].clone())
            .collect(),
        independent: merge_sequence
            .independent
            .iter()
            .map(|workspace_id| label_by_id[workspace_id].clone())
            .collect(),
        cycle_note: (status == MergeOrderStatus::Cycle)
            .then(|| "merge-order fallback only; dependency graph contains a cycle".to_string()),
        incomplete_pairs: incomplete_pairs.to_vec(),
    }
}

fn format_score(score: OrthogonalityScore) -> &'static str {
    match score {
        OrthogonalityScore::Green => "green",
        OrthogonalityScore::Yellow => "yellow",
        OrthogonalityScore::Red => "red",
        OrthogonalityScore::Black => "black",
    }
}

fn format_change_type(change_type: ChangeType) -> &'static str {
    match change_type {
        ChangeType::Added => "added",
        ChangeType::Modified => "modified",
        ChangeType::Deleted => "deleted",
        ChangeType::Renamed => "renamed",
    }
}

fn format_schema_category(category: SchemaCategory) -> &'static str {
    match category {
        SchemaCategory::Migration => "migration",
        SchemaCategory::PackageDep => "package_dep",
        SchemaCategory::EnvConfig => "env_config",
        SchemaCategory::Route => "route",
        SchemaCategory::CI => "ci",
    }
}

fn format_export_delta(delta: &ExportDelta) -> String {
    match delta {
        ExportDelta::Added(symbol) => format!("{} (added)", symbol.name),
        ExportDelta::Removed(symbol) => format!("{} (removed)", symbol.name),
        ExportDelta::SignatureChanged { symbol_name, .. } => {
            format!("{symbol_name} (signature changed)")
        }
    }
}

fn format_usage(location: &Location) -> String {
    format!("line {}", location.line)
}

fn overlap_lines(a_range: &grove_lib::LineRange, b_range: &grove_lib::LineRange) -> u32 {
    let start = a_range.start.max(b_range.start);
    let end = a_range.end.min(b_range.end);
    if start > end { 0 } else { end - start + 1 }
}

#[derive(Debug, Clone)]
struct RefSpec {
    ref_name: String,
    label: String,
}

impl RefSpec {
    fn parse(raw: &str) -> Result<Self, CommandError> {
        if let Some((ref_name, label)) = raw.split_once('=') {
            let ref_name = ref_name.trim();
            let label = label.trim();
            if ref_name.is_empty() || label.is_empty() {
                return Err(CommandError::InvalidInput(format!(
                    "invalid ref spec `{raw}`"
                )));
            }
            Ok(Self {
                ref_name: ref_name.to_string(),
                label: label.to_string(),
            })
        } else {
            let ref_name = raw.trim();
            if ref_name.is_empty() {
                return Err(CommandError::InvalidInput(
                    "ref cannot be empty".to_string(),
                ));
            }
            Ok(Self {
                ref_name: ref_name.to_string(),
                label: ref_name.to_string(),
            })
        }
    }
}

#[derive(Debug, Clone)]
struct AnalysisTarget {
    ref_name: String,
    label: String,
    workspace_id: WorkspaceId,
    changeset: Arc<WorkspaceChangeset>,
}

enum PreparedTarget {
    Ready(AnalysisTarget),
    Skipped(CiSkippedRefDto),
}

enum PairExecution {
    Completed(grove_lib::WorkspacePairAnalysis),
    TimedOut,
}

#[derive(Debug)]
struct DiffFileStatus {
    path: PathBuf,
    old_path: Option<PathBuf>,
    change_type: ChangeType,
}

struct GitRepo {
    repo: gix::Repository,
    root: PathBuf,
}

#[derive(Debug, thiserror::Error)]
enum CiGitError {
    #[error("failed to resolve revision `{spec}`: {detail}")]
    ResolveRevision { spec: String, detail: String },
    #[error("failed to find git object `{oid}`: {detail}")]
    FindObject { oid: String, detail: String },
    #[error("failed to peel `{target}` to a tree: {detail}")]
    PeelToTree { target: String, detail: String },
    #[error("failed to compute merge base for `{left}` and `{right}`: {detail}")]
    MergeBase {
        left: String,
        right: String,
        detail: String,
    },
    #[error("failed to diff trees `{old_tree}` and `{new_tree}`: {detail}")]
    DiffTreeToTree {
        old_tree: String,
        new_tree: String,
        detail: String,
    },
}

impl GitRepo {
    fn open(path: &Path) -> Result<Self, CommandError> {
        let repo = gix::open(path).map_err(|error| {
            CommandError::InvalidInput(format!(
                "failed to open git repository from `{}`: {error}",
                path.display()
            ))
        })?;
        let root = repo
            .workdir()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| repo.path().to_path_buf());

        Ok(Self { repo, root })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn workspace_namespace(&self) -> Uuid {
        let canonical = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        Uuid::new_v5(&Uuid::NAMESPACE_URL, canonical.to_string_lossy().as_bytes())
    }

    fn resolve_oid(&self, spec: &str) -> Result<gix::ObjectId, CiGitError> {
        self.repo
            .rev_parse_single(spec.as_bytes())
            .map(|id| id.detach())
            .map_err(|error| CiGitError::ResolveRevision {
                spec: spec.to_string(),
                detail: error.to_string(),
            })
    }

    fn tree_from_oid(&self, oid: gix::ObjectId) -> Result<gix::Tree<'_>, CiGitError> {
        self.repo
            .find_object(oid)
            .map_err(|error| CiGitError::FindObject {
                oid: oid.to_hex().to_string(),
                detail: error.to_string(),
            })?
            .peel_to_tree()
            .map_err(|error| CiGitError::PeelToTree {
                target: oid.to_hex().to_string(),
                detail: error.to_string(),
            })
    }

    fn resolve_tree(&self, revision: &str) -> Result<gix::Tree<'_>, CiGitError> {
        let oid = self.resolve_oid(revision)?;
        self.tree_from_oid(oid)
    }

    fn merge_base(
        &self,
        left: gix::ObjectId,
        right: gix::ObjectId,
    ) -> Result<gix::ObjectId, CiGitError> {
        self.repo
            .merge_base(left, right)
            .map(|id| id.detach())
            .map_err(|error| CiGitError::MergeBase {
                left: left.to_hex().to_string(),
                right: right.to_hex().to_string(),
                detail: error.to_string(),
            })
    }

    fn read_blob(&self, tree: &mut gix::Tree<'_>, path: &Path) -> Option<Vec<u8>> {
        let entry = tree.peel_to_entry_by_path(path).ok()??;
        let object = entry.object().ok()?;
        Some(object.data.to_vec())
    }

    fn diff_name_status(
        &self,
        old_tree: &gix::Tree<'_>,
        new_tree: &gix::Tree<'_>,
    ) -> Result<Vec<DiffFileStatus>, CiGitError> {
        let changes = self
            .repo
            .diff_tree_to_tree(Some(old_tree), Some(new_tree), None)
            .map_err(|error| CiGitError::DiffTreeToTree {
                old_tree: old_tree.id.to_hex().to_string(),
                new_tree: new_tree.id.to_hex().to_string(),
                detail: error.to_string(),
            })?;

        let mut statuses = Vec::new();
        for change in changes {
            use gix::object::tree::diff::ChangeDetached;

            match change {
                ChangeDetached::Addition {
                    location,
                    entry_mode,
                    ..
                } => {
                    if entry_mode.is_tree() {
                        continue;
                    }
                    statuses.push(DiffFileStatus {
                        path: PathBuf::from(location.to_string()),
                        old_path: None,
                        change_type: ChangeType::Added,
                    });
                }
                ChangeDetached::Deletion {
                    location,
                    entry_mode,
                    ..
                } => {
                    if entry_mode.is_tree() {
                        continue;
                    }
                    statuses.push(DiffFileStatus {
                        path: PathBuf::from(location.to_string()),
                        old_path: None,
                        change_type: ChangeType::Deleted,
                    });
                }
                ChangeDetached::Modification {
                    location,
                    entry_mode,
                    ..
                } => {
                    if entry_mode.is_tree() {
                        continue;
                    }
                    statuses.push(DiffFileStatus {
                        path: PathBuf::from(location.to_string()),
                        old_path: None,
                        change_type: ChangeType::Modified,
                    });
                }
                ChangeDetached::Rewrite {
                    source_location,
                    location,
                    entry_mode,
                    ..
                } => {
                    if entry_mode.is_tree() {
                        continue;
                    }
                    statuses.push(DiffFileStatus {
                        path: PathBuf::from(location.to_string()),
                        old_path: Some(PathBuf::from(source_location.to_string())),
                        change_type: ChangeType::Renamed,
                    });
                }
            }
        }

        Ok(statuses)
    }

    fn count_left_right(
        &self,
        left: gix::ObjectId,
        right: gix::ObjectId,
    ) -> Result<(u32, u32), CommandError> {
        let range = format!("{}...{}", left.to_hex(), right.to_hex());
        let output = Command::new("git")
            .current_dir(&self.root)
            .args(["rev-list", "--left-right", "--count", &range])
            .output()
            .map_err(|error| {
                CommandError::AnalysisError(format!(
                    "failed to run `git rev-list --left-right --count {range}`: {error}"
                ))
            })?;

        if !output.status.success() {
            return Err(CommandError::AnalysisError(format!(
                "`git rev-list --left-right --count {range}` failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let stdout = String::from_utf8(output.stdout).map_err(|error| {
            CommandError::AnalysisError(format!(
                "invalid utf-8 from `git rev-list --left-right --count {range}`: {error}"
            ))
        })?;
        parse_left_right_counts(stdout.trim()).ok_or_else(|| {
            CommandError::AnalysisError(format!(
                "unexpected left/right count output for `{range}`: {stdout}"
            ))
        })
    }
}

fn parse_left_right_counts(value: &str) -> Option<(u32, u32)> {
    let mut parts = value.split_whitespace();
    let left = parts.next()?.parse().ok()?;
    let right = parts.next()?.parse().ok()?;
    Some((left, right))
}

fn should_force_timeout(left_ref: &str, right_ref: &str) -> bool {
    let Some(raw_pairs) = std::env::var_os("GROVE_CI_TEST_TIMEOUT_PAIRS") else {
        return false;
    };

    let pair = canonical_pair(left_ref, right_ref);
    raw_pairs
        .to_string_lossy()
        .split(',')
        .filter_map(|entry| entry.split_once('|'))
        .map(|(left, right)| canonical_pair(left.trim(), right.trim()))
        .any(|candidate| candidate == pair)
}

fn canonical_pair<'a>(left: &'a str, right: &'a str) -> (&'a str, &'a str) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

#[derive(Debug, Serialize)]
struct CiAnalyzeOutput {
    base: String,
    refs: Vec<CiRefDto>,
    pairs: Vec<CiPairDto>,
    merge_order: CiMergeOrderDto,
    skipped: Vec<CiSkippedRefDto>,
}

#[derive(Debug, Serialize)]
struct CiRefDto {
    #[serde(rename = "ref")]
    r#ref: String,
    label: String,
}

#[derive(Debug, Serialize)]
struct CiPairDto {
    a: String,
    b: String,
    score: Option<String>,
    overlaps: Vec<CiOverlapDto>,
    #[serde(default, skip_serializing_if = "is_false")]
    timed_out: bool,
}

impl CiPairDto {
    fn from_analysis(
        analysis: &grove_lib::WorkspacePairAnalysis,
        label_by_id: &HashMap<WorkspaceId, String>,
    ) -> Result<Self, CommandError> {
        let a = label_by_id
            .get(&analysis.workspace_a)
            .cloned()
            .ok_or_else(|| {
                CommandError::AnalysisError(format!(
                    "missing label for workspace {}",
                    analysis.workspace_a
                ))
            })?;
        let b = label_by_id
            .get(&analysis.workspace_b)
            .cloned()
            .ok_or_else(|| {
                CommandError::AnalysisError(format!(
                    "missing label for workspace {}",
                    analysis.workspace_b
                ))
            })?;

        let overlaps = analysis
            .overlaps
            .iter()
            .map(|overlap| CiOverlapDto::from_overlap(overlap, label_by_id))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            a,
            b,
            score: Some(format_score(analysis.score).to_string()),
            overlaps,
            timed_out: false,
        })
    }

    fn timed_out(a: String, b: String) -> Self {
        Self {
            a,
            b,
            score: None,
            overlaps: Vec::new(),
            timed_out: true,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CiOverlapDto {
    File {
        path: String,
        a_change: String,
        b_change: String,
    },
    Hunk {
        path: String,
        a_range: [u32; 2],
        b_range: [u32; 2],
        overlap_lines: u32,
    },
    Symbol {
        path: String,
        symbol: String,
        a_modification: String,
        b_modification: String,
    },
    Dependency {
        changed_in: String,
        changed_file: String,
        changed_export: String,
        affected_file: String,
        affected_usages: Vec<String>,
    },
    Schema {
        category: String,
        a_file: String,
        b_file: String,
        detail: String,
    },
}

impl CiOverlapDto {
    fn from_overlap(
        overlap: &Overlap,
        label_by_id: &HashMap<WorkspaceId, String>,
    ) -> Result<Self, CommandError> {
        match overlap {
            Overlap::File {
                path,
                a_change,
                b_change,
            } => Ok(Self::File {
                path: path.display().to_string(),
                a_change: format_change_type(*a_change).to_string(),
                b_change: format_change_type(*b_change).to_string(),
            }),
            Overlap::Hunk {
                path,
                a_range,
                b_range,
                ..
            } => Ok(Self::Hunk {
                path: path.display().to_string(),
                a_range: [a_range.start, a_range.end],
                b_range: [b_range.start, b_range.end],
                overlap_lines: overlap_lines(a_range, b_range),
            }),
            Overlap::Symbol {
                path,
                symbol_name,
                a_modification,
                b_modification,
            } => Ok(Self::Symbol {
                path: path.display().to_string(),
                symbol: symbol_name.clone(),
                a_modification: a_modification.clone(),
                b_modification: b_modification.clone(),
            }),
            Overlap::Dependency {
                changed_in,
                changed_file,
                changed_export,
                affected_file,
                affected_usage,
            } => {
                let changed_in = label_by_id.get(changed_in).cloned().ok_or_else(|| {
                    CommandError::AnalysisError(format!(
                        "missing dependency overlap label for workspace {changed_in}"
                    ))
                })?;

                Ok(Self::Dependency {
                    changed_in,
                    changed_file: changed_file.display().to_string(),
                    changed_export: format_export_delta(changed_export),
                    affected_file: affected_file.display().to_string(),
                    affected_usages: affected_usage.iter().map(format_usage).collect(),
                })
            }
            Overlap::Schema {
                category,
                a_file,
                b_file,
                detail,
            } => Ok(Self::Schema {
                category: format_schema_category(*category).to_string(),
                a_file: a_file.display().to_string(),
                b_file: b_file.display().to_string(),
                detail: detail.clone(),
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct CiIncompletePairDto {
    a: String,
    b: String,
}

#[derive(Debug, Serialize)]
struct CiMergeOrderDto {
    status: MergeOrderStatus,
    sequenced: Vec<String>,
    independent: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cycle_note: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    incomplete_pairs: Vec<CiIncompletePairDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum MergeOrderStatus {
    Complete,
    Cycle,
    Partial,
    Unavailable,
}

#[derive(Debug, Serialize)]
struct CiSkippedRefDto {
    #[serde(rename = "ref")]
    r#ref: String,
    label: String,
    reason: String,
}

fn is_false(value: &bool) -> bool {
    !*value
}

const HUNK_PROXIMITY_THRESHOLD: u32 = 5;
const MAX_FILE_SIZE_BYTES: u64 = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use grove_lib::{LineRange, MergeOrder, WorkspacePairAnalysis};

    fn target(label: &str) -> AnalysisTarget {
        let workspace_id = Uuid::new_v4();
        AnalysisTarget {
            ref_name: label.to_string(),
            label: label.to_string(),
            workspace_id,
            changeset: Arc::new(WorkspaceChangeset {
                workspace_id,
                merge_base: "abc123".to_string(),
                changed_files: vec![],
                commits_ahead: 0,
                commits_behind: 0,
            }),
        }
    }

    #[test]
    fn parse_ref_spec_supports_bare_and_labeled_inputs() {
        let bare = RefSpec::parse("refs/remotes/origin/pr/42").expect("bare ref should parse");
        assert_eq!(bare.ref_name, "refs/remotes/origin/pr/42");
        assert_eq!(bare.label, "refs/remotes/origin/pr/42");

        let labeled =
            RefSpec::parse("refs/remotes/origin/pr/42=PR #42").expect("label should parse");
        assert_eq!(labeled.ref_name, "refs/remotes/origin/pr/42");
        assert_eq!(labeled.label, "PR #42");
    }

    #[test]
    fn build_merge_order_marks_unavailable_when_all_pairs_missing() {
        let targets = vec![target("A"), target("B"), target("C")];
        let incomplete = vec![
            CiIncompletePairDto {
                a: "A".to_string(),
                b: "B".to_string(),
            },
            CiIncompletePairDto {
                a: "A".to_string(),
                b: "C".to_string(),
            },
            CiIncompletePairDto {
                a: "B".to_string(),
                b: "C".to_string(),
            },
        ];

        let merge_order = build_merge_order_output(&targets, &[], &incomplete);

        assert_eq!(merge_order.status, MergeOrderStatus::Unavailable);
        assert_eq!(merge_order.incomplete_pairs.len(), 3);
    }

    #[test]
    fn build_merge_order_marks_partial_when_only_some_pairs_missing() {
        let targets = vec![target("A"), target("B"), target("C")];
        let analysis = WorkspacePairAnalysis {
            workspace_a: targets[0].workspace_id,
            workspace_b: targets[1].workspace_id,
            score: OrthogonalityScore::Yellow,
            overlaps: vec![],
            merge_order_hint: MergeOrder::AFirst,
            last_computed: Utc::now(),
        };

        let merge_order = build_merge_order_output(
            &targets,
            &[analysis],
            &[CiIncompletePairDto {
                a: "A".to_string(),
                b: "C".to_string(),
            }],
        );

        assert_eq!(merge_order.status, MergeOrderStatus::Partial);
        assert_eq!(merge_order.incomplete_pairs.len(), 1);
    }

    #[test]
    fn overlap_dto_flattens_hunk_overlap() {
        let overlap = Overlap::Hunk {
            path: PathBuf::from("src/lib.rs"),
            a_range: LineRange { start: 4, end: 10 },
            b_range: LineRange { start: 8, end: 12 },
            distance: 0,
        };

        let dto = CiOverlapDto::from_overlap(&overlap, &HashMap::new()).expect("dto should build");
        let encoded = serde_json::to_value(dto).expect("dto should serialize");

        assert_eq!(encoded["type"], "hunk");
        assert_eq!(encoded["overlap_lines"], 3);
    }
}
