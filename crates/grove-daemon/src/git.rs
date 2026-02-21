use std::path::{Path, PathBuf};

use grove_lib::{ChangeType, Hunk};

use crate::worker::{DiffFileStatus, WorkerError};

/// In-process git repository backed by `gix`.
///
/// Wraps `gix::Repository` and provides the exact git operations that
/// `extract_changeset` needs, eliminating subprocess overhead.
pub(crate) struct GitRepo {
    repo: gix::Repository,
}

impl GitRepo {
    /// Open the repository at `worktree_path`.
    pub fn open(worktree_path: &Path) -> Result<Self, WorkerError> {
        let repo = gix::open(worktree_path).map_err(|e| WorkerError::Gix {
            context: "open",
            repo_path: worktree_path.to_path_buf(),
            detail: e.to_string(),
        })?;
        Ok(Self { repo })
    }

    /// Resolve a revision spec (e.g. "HEAD", a commit hash) to an `ObjectId`.
    pub fn resolve_oid(&self, spec: &str) -> Result<gix::ObjectId, WorkerError> {
        let repo_path = self.work_dir();
        self.repo
            .rev_parse_single(spec.as_bytes())
            .map(|id| id.detach())
            .map_err(|e| WorkerError::Gix {
                context: "rev_parse_single",
                repo_path,
                detail: e.to_string(),
            })
    }

    /// Resolve a revision to its tree object.
    pub fn resolve_tree(&self, revision: &str) -> Result<gix::Tree<'_>, WorkerError> {
        let repo_path = self.work_dir();
        let id = self.resolve_oid(revision)?;
        let obj = self.repo.find_object(id).map_err(|e| WorkerError::Gix {
            context: "find_object",
            repo_path: repo_path.clone(),
            detail: e.to_string(),
        })?;
        obj.peel_to_tree().map_err(|e| WorkerError::Gix {
            context: "peel_to_tree",
            repo_path,
            detail: e.to_string(),
        })
    }

    /// Read a blob from the given tree at `path`. Returns `None` if the path
    /// doesn't exist in the tree (e.g. for newly added files).
    pub fn read_blob(&self, tree: &mut gix::Tree<'_>, path: &Path) -> Option<Vec<u8>> {
        let entry = tree.peel_to_entry_by_path(path).ok()??;
        let obj = entry.object().ok()?;
        Some(obj.data.to_vec())
    }

    /// Compute the merge-base between two revisions.
    pub fn merge_base(&self, rev_a: &str, rev_b: &str) -> Result<String, WorkerError> {
        let repo_path = self.work_dir();
        let id_a = self.resolve_oid(rev_a)?;
        let id_b = self.resolve_oid(rev_b)?;

        self.repo
            .merge_base(id_a, id_b)
            .map(|id| id.to_hex().to_string())
            .map_err(|e| WorkerError::Gix {
                context: "merge_base",
                repo_path,
                detail: e.to_string(),
            })
    }

    /// Compute file-level diff between two trees (equivalent to `git diff --name-status --find-renames`).
    pub fn diff_name_status(
        &self,
        old_tree: &gix::Tree<'_>,
        new_tree: &gix::Tree<'_>,
    ) -> Result<Vec<DiffFileStatus>, WorkerError> {
        let repo_path = self.work_dir();
        let changes = self
            .repo
            .diff_tree_to_tree(Some(old_tree), Some(new_tree), None)
            .map_err(|e| WorkerError::Gix {
                context: "diff_tree_to_tree",
                repo_path,
                detail: e.to_string(),
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

    /// Detect files that differ between HEAD and the working tree (staged + unstaged).
    /// Returns relative paths of dirty files mapped to their change type.
    /// Uses `git status --porcelain=v1 -z` subprocess (same pattern as rev-list).
    pub fn worktree_status(&self) -> Result<Vec<DiffFileStatus>, WorkerError> {
        let repo_path = self.work_dir();
        let output = crate::worker::git_output(
            &repo_path,
            ["status", "--porcelain=v1", "-z", "--no-renames"],
            "status --porcelain",
        )?;

        let mut statuses = Vec::new();
        // Porcelain v1 with -z: entries separated by NUL, each entry is "XY path"
        for entry in output.split('\0') {
            if entry.len() < 4 {
                continue; // "XY " + at least 1 char path
            }
            let index_status = entry.as_bytes()[0];
            let worktree_status = entry.as_bytes()[1];
            let path = PathBuf::from(&entry[3..]);

            // Determine change type from the most "dirty" indicator.
            // Prefer worktree status over index status (unstaged > staged).
            let change_type = match (index_status, worktree_status) {
                (b'D', _) | (_, b'D') => ChangeType::Deleted,
                (b'A', _) | (b'?', _) => ChangeType::Added,
                _ => ChangeType::Modified,
            };

            statuses.push(DiffFileStatus {
                path,
                old_path: None,
                change_type,
            });
        }

        Ok(statuses)
    }

    fn work_dir(&self) -> PathBuf {
        self.repo
            .workdir()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }
}

/// Enumerate all worktrees (main + linked) using gix.
/// Returns Workspace structs with deterministic IDs (same as socket.rs sync_worktrees).
pub(crate) fn enumerate_worktrees(
    repo_path: &Path,
) -> Result<Vec<grove_lib::Workspace>, WorkerError> {
    let repo = gix::open(repo_path).map_err(|e| WorkerError::Gix {
        context: "enumerate_worktrees",
        repo_path: repo_path.to_path_buf(),
        detail: e.to_string(),
    })?;

    let mut worktrees = Vec::new();

    // Main worktree
    if let Some(ws) = workspace_from_repo(&repo) {
        worktrees.push(ws);
    }

    // Linked worktrees
    if let Ok(proxies) = repo.worktrees() {
        for proxy in proxies {
            if let Ok(linked) = proxy.into_repo_with_possibly_inaccessible_worktree()
                && let Some(ws) = workspace_from_repo(&linked)
            {
                worktrees.push(ws);
            }
        }
    }

    Ok(worktrees)
}

fn workspace_from_repo(repo: &gix::Repository) -> Option<grove_lib::Workspace> {
    let path = repo.workdir()?.to_path_buf();
    let head_ref = repo.head().ok()?;
    let branch = head_ref
        .referent_name()
        .map(|name| name.as_bstr().to_string());
    let name = match &branch {
        Some(b) => b.strip_prefix("refs/heads/").unwrap_or(b).to_string(),
        None => path.file_name()?.to_string_lossy().to_string(),
    };

    let id = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        path.to_string_lossy().as_bytes(),
    );

    Some(grove_lib::Workspace {
        id,
        name,
        branch: branch.unwrap_or_default(),
        path,
        base_ref: String::new(),
        created_at: chrono::Utc::now(),
        last_activity: chrono::Utc::now(),
        metadata: grove_lib::WorkspaceMetadata::default(),
    })
}

/// Compute unified diff hunks from old/new content using the `similar` crate.
///
/// Equivalent to `git diff --unified=0` but computed in-process from blob content
/// we already have, eliminating the need for a subprocess call.
pub(crate) fn compute_hunks_from_content(old: Option<&[u8]>, new: Option<&[u8]>) -> Vec<Hunk> {
    let old_str = old.map(|b| String::from_utf8_lossy(b)).unwrap_or_default();
    let new_str = new.map(|b| String::from_utf8_lossy(b)).unwrap_or_default();

    let diff = similar::TextDiff::from_lines(old_str.as_ref(), new_str.as_ref());
    // grouped_ops(0) gives us --unified=0 equivalent (no context lines)
    let groups = diff.grouped_ops(0);

    let mut hunks = Vec::new();
    for group in groups {
        let mut old_start = u32::MAX;
        let mut old_end = 0u32;
        let mut new_start = u32::MAX;
        let mut new_end = 0u32;

        for op in &group {
            let os = op.old_range().start as u32;
            let oe = op.old_range().end as u32;
            let ns = op.new_range().start as u32;
            let ne = op.new_range().end as u32;

            // 0-indexed to 1-indexed
            old_start = old_start.min(os + 1);
            old_end = old_end.max(oe);
            new_start = new_start.min(ns + 1);
            new_end = new_end.max(ne);
        }

        let old_lines = old_end.saturating_sub(old_start.saturating_sub(1));
        let new_lines = new_end.saturating_sub(new_start.saturating_sub(1));

        // Fix start for pure insertions/deletions at line 0
        if old_start == u32::MAX {
            old_start = 0;
        }
        if new_start == u32::MAX {
            new_start = 0;
        }

        hunks.push(Hunk {
            old_start,
            old_lines,
            new_start,
            new_lines,
        });
    }

    hunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Create a temp git repo with an initial commit.
    fn init_temp_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "Test")
                .env("GIT_AUTHOR_EMAIL", "test@test.com")
                .env("GIT_COMMITTER_NAME", "Test")
                .env("GIT_COMMITTER_EMAIL", "test@test.com")
                .output()
                .unwrap()
        };
        run(&["init", "-b", "main"]);
        std::fs::write(dir.path().join("README.md"), "# test\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-m", "init"]);
        dir
    }

    #[test]
    fn enumerate_worktrees_finds_main_worktree() {
        let dir = init_temp_repo();
        let canon_dir = dir.path().canonicalize().unwrap();
        let worktrees = enumerate_worktrees(&canon_dir).unwrap();

        assert_eq!(worktrees.len(), 1);
        assert_eq!(worktrees[0].path.canonicalize().unwrap(), canon_dir);
        assert!(worktrees[0].branch.contains("main"));
    }

    #[test]
    fn enumerate_worktrees_finds_main_and_linked() {
        let dir = init_temp_repo();
        // Canonicalize to handle macOS /var -> /private/var symlinks
        let canon_dir = dir.path().canonicalize().unwrap();
        let linked_path = canon_dir.join("linked-wt");

        let output = Command::new("git")
            .args([
                "worktree",
                "add",
                linked_path.to_str().unwrap(),
                "-b",
                "feature",
            ])
            .current_dir(&canon_dir)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let worktrees = enumerate_worktrees(&canon_dir).unwrap();

        assert_eq!(worktrees.len(), 2);
        let paths: Vec<_> = worktrees
            .iter()
            .map(|w| w.path.canonicalize().unwrap_or(w.path.clone()))
            .collect();
        assert!(
            paths.contains(&canon_dir),
            "main worktree not found in {paths:?}"
        );
        assert!(
            paths.contains(&linked_path),
            "linked worktree not found in {paths:?}"
        );
    }

    #[test]
    fn enumerate_worktrees_ids_are_deterministic() {
        let dir = init_temp_repo();
        let canon_dir = dir.path().canonicalize().unwrap();
        let wt1 = enumerate_worktrees(&canon_dir).unwrap();
        let wt2 = enumerate_worktrees(&canon_dir).unwrap();

        assert_eq!(wt1.len(), wt2.len());
        for (a, b) in wt1.iter().zip(wt2.iter()) {
            assert_eq!(a.id, b.id, "IDs should be deterministic for same path");
        }
    }

    #[test]
    fn enumerate_worktrees_id_matches_uuid_v5_scheme() {
        let dir = init_temp_repo();
        let canon_dir = dir.path().canonicalize().unwrap();
        let worktrees = enumerate_worktrees(&canon_dir).unwrap();

        // The ID is computed from the path that gix returns (which may differ
        // from canon_dir due to gix's own canonicalization). Verify it matches
        // the UUID v5 scheme using the actual path gix reported.
        let expected_id = uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_URL,
            worktrees[0].path.to_string_lossy().as_bytes(),
        );
        assert_eq!(worktrees[0].id, expected_id);
    }
}
