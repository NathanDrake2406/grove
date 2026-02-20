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
}

pub trait FileSystem: Send + Sync {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError>;
    fn exists(&self, path: &Path) -> bool;
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError>;
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

/// Memory-mapped filesystem for production use.
pub struct MmapFileSystem;

impl FileSystem for MmapFileSystem {
    fn read_file(&self, path: &Path) -> Result<Bytes, FsError> {
        let data = std::fs::read(path)?;
        Ok(Bytes::from(data))
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(path)? {
            entries.push(entry?.path());
        }
        entries.sort();
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
