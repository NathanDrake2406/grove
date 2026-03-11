use bytes::Bytes;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FsError {
    #[error("file not found: {0}")]
    NotFound(PathBuf),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("git error during {context} in {repo_path}: {detail}")]
    Git {
        context: &'static str,
        repo_path: PathBuf,
        detail: String,
    },
    #[error("internal state error: {0}")]
    State(String),
}

pub trait FileSystem: Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError>;
    fn exists(&self, path: &Path) -> bool;
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError>;
}

/// Read-only filesystem backed by a pinned git tree.
#[derive(Debug)]
pub struct GitObjectFileSystem {
    repo: gix::ThreadSafeRepository,
    tree_id: gix::ObjectId,
    repo_path: PathBuf,
}

impl GitObjectFileSystem {
    pub fn open(repo_path: &Path, revision: &str) -> Result<Self, FsError> {
        let repo = gix::open(repo_path)
            .map_err(|err| FsError::Git {
                context: "open",
                repo_path: repo_path.to_path_buf(),
                detail: err.to_string(),
            })?
            .into_sync();

        Self::new(repo, revision)
    }

    pub fn new(repo: gix::ThreadSafeRepository, revision: &str) -> Result<Self, FsError> {
        let repo_path = repo
            .work_dir()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| repo.path().to_path_buf());
        let local_repo = repo.to_thread_local();

        let object_id = local_repo
            .rev_parse_single(revision.as_bytes())
            .map_err(|err| FsError::Git {
                context: "rev_parse_single",
                repo_path: repo_path.clone(),
                detail: err.to_string(),
            })?
            .detach();

        let tree_id = local_repo
            .find_object(object_id)
            .map_err(|err| FsError::Git {
                context: "find_object",
                repo_path: repo_path.clone(),
                detail: err.to_string(),
            })?
            .peel_to_tree()
            .map_err(|err| FsError::Git {
                context: "peel_to_tree",
                repo_path: repo_path.clone(),
                detail: err.to_string(),
            })?
            .id;

        Ok(Self {
            repo,
            tree_id,
            repo_path,
        })
    }
}

/// In-memory filesystem for testing. Deterministic, no disk I/O.
#[derive(Debug, Default, Clone)]
pub struct InMemoryFileSystem {
    files: HashMap<PathBuf, Vec<u8>>,
}

impl InMemoryFileSystem {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_file(&mut self, path: impl Into<PathBuf>, content: impl Into<Vec<u8>>) {
        self.files.insert(path.into(), content.into());
    }
}

impl FileSystem for InMemoryFileSystem {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError> {
        self.files
            .get(path)
            .map(|data| Bytes::copy_from_slice(data))
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))
    }

    fn exists(&self, path: &Path) -> bool {
        self.files.contains_key(path)
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let mut entries: Vec<PathBuf> = self
            .files
            .keys()
            .filter(|p| {
                if let Ok(rest) = p.strip_prefix(path) {
                    // Direct children only (no nested path separators)
                    rest.components().count() == 1
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        entries.sort();
        Ok(entries)
    }
}

impl FileSystem for GitObjectFileSystem {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError> {
        let repo = self.repo.to_thread_local();
        let tree = repo
            .find_object(self.tree_id)
            .map_err(|err| FsError::Git {
                context: "find_object",
                repo_path: self.repo_path.clone(),
                detail: err.to_string(),
            })?
            .try_into_tree()
            .map_err(|err| FsError::Git {
                context: "try_into_tree",
                repo_path: self.repo_path.clone(),
                detail: err.to_string(),
            })?;
        let entry = tree
            .lookup_entry_by_path(path)
            .map_err(|err| FsError::Git {
                context: "lookup_entry_by_path",
                repo_path: self.repo_path.clone(),
                detail: err.to_string(),
            })?
            .ok_or_else(|| FsError::NotFound(path.to_path_buf()))?;
        let object = entry.object().map_err(|err| FsError::Git {
            context: "entry.object",
            repo_path: self.repo_path.clone(),
            detail: err.to_string(),
        })?;
        let blob = object
            .try_into_blob()
            .map_err(|_| FsError::NotFound(path.to_path_buf()))?;
        Ok(Bytes::copy_from_slice(&blob.data))
    }

    fn exists(&self, path: &Path) -> bool {
        if path.as_os_str().is_empty() {
            return true;
        }

        let repo = self.repo.to_thread_local();
        let object = match repo.find_object(self.tree_id) {
            Ok(object) => object,
            Err(_) => return false,
        };
        let tree = match object.try_into_tree() {
            Ok(tree) => tree,
            Err(_) => return false,
        };

        tree.lookup_entry_by_path(path)
            .map(|entry| entry.is_some())
            .unwrap_or(false)
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let repo = self.repo.to_thread_local();
        let root = repo
            .find_object(self.tree_id)
            .map_err(|err| FsError::Git {
                context: "find_object",
                repo_path: self.repo_path.clone(),
                detail: err.to_string(),
            })?
            .try_into_tree()
            .map_err(|err| FsError::Git {
                context: "try_into_tree",
                repo_path: self.repo_path.clone(),
                detail: err.to_string(),
            })?;
        let tree = if path.as_os_str().is_empty() {
            root
        } else {
            let entry = root
                .lookup_entry_by_path(path)
                .map_err(|err| FsError::Git {
                    context: "lookup_entry_by_path",
                    repo_path: self.repo_path.clone(),
                    detail: err.to_string(),
                })?
                .ok_or_else(|| FsError::NotFound(path.to_path_buf()))?;
            entry
                .object()
                .map_err(|err| FsError::Git {
                    context: "entry.object",
                    repo_path: self.repo_path.clone(),
                    detail: err.to_string(),
                })?
                .try_into_tree()
                .map_err(|_| FsError::NotFound(path.to_path_buf()))?
        };
        let prefix = if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        };

        let mut entries = Vec::new();
        for entry in tree.iter() {
            let entry = entry.map_err(|err| FsError::Git {
                context: "tree.iter",
                repo_path: self.repo_path.clone(),
                detail: err.to_string(),
            })?;
            let child_name = PathBuf::from(entry.filename().to_string());
            let child_path = match prefix {
                Some(prefix) => prefix.join(child_name),
                None => child_name,
            };
            entries.push(child_path);
        }
        entries.sort();
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tempfile::tempdir;

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

    fn write_file(path: &Path, content: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent dirs should be created");
        }
        std::fs::write(path, content).expect("file should be written");
    }

    fn init_git_repo() -> (tempfile::TempDir, PathBuf) {
        let temp = tempdir().expect("temp dir should be created");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("repo dir should be created");

        run_git(&repo, &["init", "-b", "main"]);
        run_git(&repo, &["config", "user.email", "grove@example.com"]);
        run_git(&repo, &["config", "user.name", "Grove Tests"]);

        (temp, repo)
    }

    #[test]
    fn in_memory_fs_read_existing_file() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("src/main.rs"), b"fn main() {}".to_vec());

        let content = fs.read_file(Path::new("src/main.rs")).unwrap();
        assert_eq!(&content[..], b"fn main() {}");
    }

    #[test]
    fn in_memory_fs_read_missing_file() {
        let fs = InMemoryFileSystem::new();
        let result = fs.read_file(Path::new("missing.rs"));
        assert!(result.is_err());
    }

    #[test]
    fn in_memory_fs_exists() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("a.rs"), b"".to_vec());

        assert!(fs.exists(Path::new("a.rs")));
        assert!(!fs.exists(Path::new("b.rs")));
    }

    #[test]
    fn in_memory_fs_list_dir() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("src/a.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("src/b.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("src/nested/c.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("other/d.rs"), b"".to_vec());

        let entries = fs.list_dir(Path::new("src")).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&PathBuf::from("src/a.rs")));
        assert!(entries.contains(&PathBuf::from("src/b.rs")));
    }

    #[test]
    fn in_memory_fs_read_missing_file_reports_exact_path() {
        let fs = InMemoryFileSystem::new();
        let missing = PathBuf::from("src/missing.bin");

        let err = fs.read_file(&missing).unwrap_err();
        match err {
            FsError::NotFound(path) => assert_eq!(path, missing),
            other => panic!("expected FsError::NotFound, got {other:?}"),
        }
    }

    #[test]
    fn in_memory_fs_preserves_malformed_bytes_and_is_idempotent() {
        let mut fs = InMemoryFileSystem::new();
        let raw = vec![0x00, 0xFF, 0xC3, 0x28, 0x80, b'\n'];
        fs.add_file(PathBuf::from("blob.bin"), raw.clone());

        let first = fs.read_file(Path::new("blob.bin")).unwrap();
        let second = fs.read_file(Path::new("blob.bin")).unwrap();

        assert_eq!(first.as_ref(), raw.as_slice());
        assert_eq!(second.as_ref(), raw.as_slice());
        assert_eq!(first, second);
    }

    #[test]
    fn in_memory_fs_list_dir_is_sorted_and_deterministic() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("src/zeta.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("src/alpha.rs"), b"".to_vec());
        fs.add_file(PathBuf::from("src/mid.rs"), b"".to_vec());

        let first = fs.list_dir(Path::new("src")).unwrap();
        let second = fs.list_dir(Path::new("src")).unwrap();

        assert_eq!(
            first,
            vec![
                PathBuf::from("src/alpha.rs"),
                PathBuf::from("src/mid.rs"),
                PathBuf::from("src/zeta.rs"),
            ]
        );
        assert_eq!(first, second);
    }

    #[test]
    fn in_memory_fs_list_dir_for_missing_prefix_is_empty() {
        let mut fs = InMemoryFileSystem::new();
        fs.add_file(PathBuf::from("src/a.rs"), b"".to_vec());

        let entries = fs.list_dir(Path::new("does-not-exist")).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn git_object_fs_reads_file_from_pinned_revision() {
        let (_temp, repo) = init_git_repo();
        write_file(
            &repo.join("src/lib.rs"),
            b"pub fn greeting() -> &'static str { \"hello\" }\n",
        );
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        write_file(
            &repo.join("src/lib.rs"),
            b"pub fn greeting() -> &'static str { \"updated\" }\n",
        );
        run_git(&repo, &["commit", "-am", "update"]);

        let fs = GitObjectFileSystem::open(&repo, "HEAD~1").expect("filesystem should open");
        let content = fs
            .read_file(Path::new("src/lib.rs"))
            .expect("file should read");

        assert_eq!(
            content.as_ref(),
            b"pub fn greeting() -> &'static str { \"hello\" }\n"
        );
    }

    #[test]
    fn git_object_fs_missing_file_reports_exact_path() {
        let (_temp, repo) = init_git_repo();
        write_file(&repo.join("README.md"), b"# Grove\n");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "initial"]);

        let fs = GitObjectFileSystem::open(&repo, "HEAD").expect("filesystem should open");
        let missing = PathBuf::from("src/missing.rs");

        let err = fs.read_file(&missing).expect_err("file should be missing");
        match err {
            FsError::NotFound(path) => assert_eq!(path, missing),
            other => panic!("expected FsError::NotFound, got {other:?}"),
        }
    }

    #[test]
    fn git_object_fs_preserves_raw_blob_bytes() {
        let (_temp, repo) = init_git_repo();
        let raw = vec![0x00, 0xFF, 0xC3, 0x28, 0x80, b'\n'];
        write_file(&repo.join("blob.bin"), &raw);
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "binary"]);

        let fs = GitObjectFileSystem::open(&repo, "HEAD").expect("filesystem should open");
        let first = fs
            .read_file(Path::new("blob.bin"))
            .expect("blob should read");
        let second = fs
            .read_file(Path::new("blob.bin"))
            .expect("blob should reread");

        assert_eq!(first.as_ref(), raw.as_slice());
        assert_eq!(second.as_ref(), raw.as_slice());
    }

    #[test]
    fn git_object_fs_list_dir_returns_direct_children_only() {
        let (_temp, repo) = init_git_repo();
        write_file(&repo.join("src/a.rs"), b"pub fn a() {}\n");
        write_file(&repo.join("src/nested/b.rs"), b"pub fn b() {}\n");
        write_file(&repo.join("README.md"), b"# Grove\n");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "tree"]);

        let fs = GitObjectFileSystem::open(&repo, "HEAD").expect("filesystem should open");

        let root_entries = fs.list_dir(Path::new("")).expect("root should list");
        assert_eq!(
            root_entries,
            vec![PathBuf::from("README.md"), PathBuf::from("src")]
        );

        let src_entries = fs.list_dir(Path::new("src")).expect("src should list");
        assert_eq!(
            src_entries,
            vec![PathBuf::from("src/a.rs"), PathBuf::from("src/nested")]
        );
    }

    #[test]
    fn git_object_fs_exists_checks_tree_entries() {
        let (_temp, repo) = init_git_repo();
        write_file(&repo.join("src/a.rs"), b"pub fn a() {}\n");
        run_git(&repo, &["add", "."]);
        run_git(&repo, &["commit", "-m", "tree"]);

        let fs = GitObjectFileSystem::open(&repo, "HEAD").expect("filesystem should open");

        assert!(fs.exists(Path::new("src/a.rs")));
        assert!(fs.exists(Path::new("src")));
        assert!(!fs.exists(Path::new("src/missing.rs")));
    }
}
