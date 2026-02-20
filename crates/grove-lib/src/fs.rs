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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_path(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("grove-{prefix}-{}-{nanos}", std::process::id()))
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
    fn mmap_fs_read_file_preserves_malformed_bytes() {
        let fs = MmapFileSystem;
        let temp_dir = unique_temp_path("mmap-read");
        std::fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("blob.bin");
        let raw = vec![0xFF, 0xFE, 0x00, 0x80, b'x'];
        std::fs::write(&file_path, &raw).unwrap();

        let content = fs.read_file(&file_path).unwrap();
        assert_eq!(content.as_ref(), raw.as_slice());

        std::fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn mmap_fs_list_dir_is_sorted_and_repeatable() {
        let fs = MmapFileSystem;
        let temp_dir = unique_temp_path("mmap-list");
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::write(temp_dir.join("z.txt"), b"").unwrap();
        std::fs::write(temp_dir.join("a.txt"), b"").unwrap();
        std::fs::write(temp_dir.join("m.txt"), b"").unwrap();

        let first = fs.list_dir(&temp_dir).unwrap();
        let second = fs.list_dir(&temp_dir).unwrap();

        let names: Vec<_> = first
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.txt", "m.txt", "z.txt"]);
        assert_eq!(first, second);

        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
}
