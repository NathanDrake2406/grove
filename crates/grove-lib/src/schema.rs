use crate::types::*;
use std::path::Path;

const MIGRATION_DIRS: &[&str] = &["migrations", "db/migrate", "prisma/migrations"];

pub fn classify_schema_file(path: &Path) -> Option<SchemaCategory> {
    let path_str = path.to_string_lossy();
    let filename = path.file_name()?.to_string_lossy();
    let ext = path.extension().map(|e| e.to_string_lossy().to_string());

    // Migrations
    for dir in MIGRATION_DIRS {
        if path_str.contains(dir) {
            return Some(SchemaCategory::Migration);
        }
    }
    if ext.as_deref() == Some("sql") {
        return Some(SchemaCategory::Migration);
    }

    // Package deps
    if matches!(
        filename.as_ref(),
        "package.json"
            | "package-lock.json"
            | "Cargo.toml"
            | "Cargo.lock"
            | "go.mod"
            | "go.sum"
            | "pnpm-lock.yaml"
            | "yarn.lock"
    ) {
        return Some(SchemaCategory::PackageDep);
    }

    // Env config
    if filename.starts_with(".env") {
        return Some(SchemaCategory::EnvConfig);
    }

    // CI
    if path_str.contains(".github/workflows")
        || path_str.contains(".gitlab-ci")
        || filename == "Jenkinsfile"
    {
        return Some(SchemaCategory::CI);
    }

    // Routes
    if path_str.contains("routes/") || path_str.contains("router") {
        return Some(SchemaCategory::Route);
    }

    None
}

pub fn compute_schema_overlaps(a: &WorkspaceChangeset, b: &WorkspaceChangeset) -> Vec<Overlap> {
    let mut overlaps = Vec::new();

    for a_file in &a.changed_files {
        if let Some(a_cat) = classify_schema_file(&a_file.path) {
            for b_file in &b.changed_files {
                if let Some(b_cat) = classify_schema_file(&b_file.path)
                    && a_cat == b_cat
                {
                    overlaps.push(Overlap::Schema {
                        category: a_cat,
                        a_file: a_file.path.clone(),
                        b_file: b_file.path.clone(),
                        detail: format!(
                            "Both workspaces modify {:?} files",
                            a_cat
                        ),
                    });
                }
            }
        }
    }

    overlaps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn classifies_migration_files() {
        assert_eq!(
            classify_schema_file(Path::new("migrations/001_init.sql")),
            Some(SchemaCategory::Migration)
        );
        assert_eq!(
            classify_schema_file(Path::new("db/migrate/20240101_users.sql")),
            Some(SchemaCategory::Migration)
        );
    }

    #[test]
    fn classifies_package_deps() {
        assert_eq!(
            classify_schema_file(Path::new("package.json")),
            Some(SchemaCategory::PackageDep)
        );
        assert_eq!(
            classify_schema_file(Path::new("Cargo.toml")),
            Some(SchemaCategory::PackageDep)
        );
    }

    #[test]
    fn classifies_env_config() {
        assert_eq!(
            classify_schema_file(Path::new(".env")),
            Some(SchemaCategory::EnvConfig)
        );
        assert_eq!(
            classify_schema_file(Path::new(".env.production")),
            Some(SchemaCategory::EnvConfig)
        );
    }

    #[test]
    fn classifies_ci() {
        assert_eq!(
            classify_schema_file(Path::new(".github/workflows/ci.yml")),
            Some(SchemaCategory::CI)
        );
    }

    #[test]
    fn returns_none_for_regular_files() {
        assert_eq!(classify_schema_file(Path::new("src/main.ts")), None);
        assert_eq!(classify_schema_file(Path::new("lib/utils.rs")), None);
    }

    #[test]
    fn schema_overlap_detects_same_category() {
        let a = WorkspaceChangeset {
            workspace_id: uuid::Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("package.json"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };
        let b = WorkspaceChangeset {
            workspace_id: uuid::Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: vec![FileChange {
                path: PathBuf::from("Cargo.toml"),
                change_type: ChangeType::Modified,
                hunks: vec![],
                symbols_modified: vec![],
                exports_changed: vec![],
            }],
            commits_ahead: 1,
            commits_behind: 0,
        };

        let overlaps = compute_schema_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Schema { category, .. } => assert_eq!(*category, SchemaCategory::PackageDep),
            _ => panic!("expected schema overlap"),
        }
    }
}
