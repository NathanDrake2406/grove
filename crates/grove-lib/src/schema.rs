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
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "requirements.txt"
            | "Pipfile"
            | "Pipfile.lock"
            | "poetry.lock"
            | "uv.lock"
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
                        detail: format!("Both workspaces modify {:?} files", a_cat),
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
    use uuid::Uuid;

    fn make_changeset(paths: &[&str]) -> WorkspaceChangeset {
        WorkspaceChangeset {
            workspace_id: Uuid::new_v4(),
            merge_base: "abc".into(),
            changed_files: paths
                .iter()
                .map(|path| FileChange {
                    path: PathBuf::from(path),
                    change_type: ChangeType::Modified,
                    hunks: vec![],
                    symbols_modified: vec![],
                    exports_changed: vec![],
                })
                .collect(),
            commits_ahead: 1,
            commits_behind: 0,
        }
    }

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
    fn classifies_python_package_deps() {
        for name in &[
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
        ] {
            assert_eq!(
                classify_schema_file(Path::new(name)),
                Some(SchemaCategory::PackageDep),
                "{name} should be PackageDep"
            );
        }
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
        let a = make_changeset(&["package.json"]);
        let b = make_changeset(&["Cargo.toml"]);

        let overlaps = compute_schema_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Schema { category, .. } => assert_eq!(*category, SchemaCategory::PackageDep),
            _ => panic!("expected schema overlap"),
        }
    }

    #[test]
    fn classifies_route_files() {
        assert_eq!(
            classify_schema_file(Path::new("src/routes/users.ts")),
            Some(SchemaCategory::Route)
        );
        assert_eq!(
            classify_schema_file(Path::new("src/router/index.ts")),
            Some(SchemaCategory::Route)
        );
    }

    #[test]
    fn migration_category_wins_when_multiple_patterns_match() {
        assert_eq!(
            classify_schema_file(Path::new("migrations/package.json")),
            Some(SchemaCategory::Migration)
        );
    }

    #[test]
    fn schema_overlap_empty_inputs_are_empty() {
        let a = make_changeset(&[]);
        let b = make_changeset(&[]);
        assert!(compute_schema_overlaps(&a, &b).is_empty());
    }

    #[test]
    fn schema_overlap_handles_unicode_and_nested_paths() {
        let deep = (0..55)
            .map(|i| format!("层{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let a_path = format!("{deep}/.env.prod");
        let b_path = format!("{deep}/.env.local");
        let a = make_changeset(&[&a_path]);
        let b = make_changeset(&[&b_path]);

        let overlaps = compute_schema_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 1);
        match &overlaps[0] {
            Overlap::Schema { category, .. } => assert_eq!(*category, SchemaCategory::EnvConfig),
            _ => panic!("expected schema overlap"),
        }
    }

    #[test]
    fn classify_schema_file_handles_empty_path_boundary() {
        assert_eq!(classify_schema_file(Path::new("")), None);
    }

    #[test]
    fn classify_schema_file_handles_deep_unicode_ci_paths() {
        let deep = (0..70)
            .map(|i| format!("節{i}"))
            .collect::<Vec<_>>()
            .join("/");
        let path = format!("{deep}/.github/workflows/发布.yml");
        assert_eq!(
            classify_schema_file(Path::new(&path)),
            Some(SchemaCategory::CI)
        );
    }

    #[test]
    fn schema_overlap_is_commutative_after_normalizing_file_pairs() {
        fn category_rank(category: SchemaCategory) -> u8 {
            match category {
                SchemaCategory::Migration => 0,
                SchemaCategory::PackageDep => 1,
                SchemaCategory::EnvConfig => 2,
                SchemaCategory::Route => 3,
                SchemaCategory::CI => 4,
            }
        }

        fn key(overlap: &Overlap) -> (SchemaCategory, PathBuf, PathBuf) {
            match overlap {
                Overlap::Schema {
                    category,
                    a_file,
                    b_file,
                    ..
                } => {
                    let left = a_file.clone();
                    let right = b_file.clone();
                    if left <= right {
                        (*category, left, right)
                    } else {
                        (*category, right, left)
                    }
                }
                _ => panic!("expected schema overlap"),
            }
        }

        let a = make_changeset(&[
            ".env.local",
            "migrations/001_init.sql",
            "src/routes/users.ts",
        ]);
        let b = make_changeset(&[".env.prod", "db/migrate/2.sql", "src/router/index.ts"]);

        let mut left: Vec<_> = compute_schema_overlaps(&a, &b).iter().map(key).collect();
        let mut right: Vec<_> = compute_schema_overlaps(&b, &a).iter().map(key).collect();
        left.sort_by(|l, r| {
            (category_rank(l.0), &l.1, &l.2).cmp(&(category_rank(r.0), &r.1, &r.2))
        });
        right.sort_by(|l, r| {
            (category_rank(l.0), &l.1, &l.2).cmp(&(category_rank(r.0), &r.1, &r.2))
        });
        assert_eq!(left, right);
    }

    #[test]
    fn same_category_overlap_scales_as_cross_product() {
        let mut a_paths = Vec::new();
        let mut b_paths = Vec::new();
        for i in 0..18 {
            a_paths.push(format!("migrations/{i:03}_a.sql"));
        }
        for i in 0..23 {
            b_paths.push(format!("db/migrate/{i:03}_b.sql"));
        }

        let a_refs: Vec<_> = a_paths.iter().map(String::as_str).collect();
        let b_refs: Vec<_> = b_paths.iter().map(String::as_str).collect();
        let a = make_changeset(&a_refs);
        let b = make_changeset(&b_refs);

        let overlaps = compute_schema_overlaps(&a, &b);
        assert_eq!(overlaps.len(), 18 * 23);
        assert!(overlaps.iter().all(|o| match o {
            Overlap::Schema { category, .. } => *category == SchemaCategory::Migration,
            _ => false,
        }));
    }

    #[test]
    fn mixed_categories_only_overlap_with_matching_category() {
        let a = make_changeset(&[
            "package.json",
            ".github/workflows/ci.yml",
            "src/noise.txt",
            "src/router/users.ts",
        ]);
        let b = make_changeset(&["Cargo.toml", "Jenkinsfile", "src/routes/api.ts"]);

        let overlaps = compute_schema_overlaps(&a, &b);
        let categories: Vec<_> = overlaps
            .iter()
            .map(|o| match o {
                Overlap::Schema { category, .. } => *category,
                _ => panic!("expected schema overlap"),
            })
            .collect();

        assert_eq!(categories.len(), 3);
        assert!(categories.contains(&SchemaCategory::PackageDep));
        assert!(categories.contains(&SchemaCategory::CI));
        assert!(categories.contains(&SchemaCategory::Route));
    }
}
