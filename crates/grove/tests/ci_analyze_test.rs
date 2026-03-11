use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

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
        std::fs::create_dir_all(parent).expect("parent directories should exist");
    }
    std::fs::write(path, content).expect("file should be written");
}

fn init_repo() -> tempfile::TempDir {
    let temp_dir = tempfile::tempdir().expect("temp dir should exist");
    let repo = temp_dir.path();

    run_git(repo, &["init", "-b", "main"]);
    run_git(repo, &["config", "user.email", "grove@example.com"]);
    run_git(repo, &["config", "user.name", "Grove Tests"]);

    write_file(
        &repo.join("src/api.ts"),
        "export function foo(value: number): number {\n  return value + 1;\n}\n",
    );
    write_file(
        &repo.join("src/consumer.ts"),
        "import { foo } from './api';\nexport function useFoo(): number {\n  return foo(1);\n}\n",
    );
    write_file(&repo.join("src/shared.ts"), "export const shared = 1;\n");
    write_file(&repo.join("src/a.ts"), "export const a = 'main';\n");
    write_file(&repo.join("src/b.ts"), "export const b = 'main';\n");
    write_file(&repo.join("src/c.ts"), "export const c = 'main';\n");

    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "initial"]);

    temp_dir
}

fn create_branch(repo: &Path, branch: &str, files: &[(&str, &str)]) {
    run_git(repo, &["checkout", "-b", branch, "main"]);
    for (path, content) in files {
        write_file(&repo.join(path), content);
    }
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", branch]);
    run_git(repo, &["checkout", "main"]);
}

fn run_grove(repo: &Path, args: &[&str], stdin: Option<&str>, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_grove"));
    command.args(args).current_dir(repo);
    for (key, value) in envs {
        command.env(key, value);
    }

    if let Some(stdin) = stdin {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("grove binary should spawn");
        child
            .stdin
            .as_mut()
            .expect("stdin should be piped")
            .write_all(stdin.as_bytes())
            .expect("stdin should write");
        child
            .wait_with_output()
            .expect("grove output should be collected")
    } else {
        command.output().expect("grove binary should run")
    }
}

fn parse_stdout_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "grove should succeed, stderr was: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("stdout should be valid json")
}

#[test]
fn ci_analyze_reads_stdin_refs_and_bypasses_bootstrap() {
    let repo_dir = init_repo();
    let repo = repo_dir.path();

    create_branch(
        repo,
        "feature-a",
        &[("src/a.ts", "export const a = 'feature-a';\n")],
    );
    create_branch(
        repo,
        "feature-b",
        &[("src/b.ts", "export const b = 'feature-b';\n")],
    );
    create_branch(
        repo,
        "feature-c",
        &[("src/c.ts", "export const c = 'feature-c';\n")],
    );

    let output = run_grove(
        repo,
        &["ci", "analyze", "--refs-from-stdin"],
        Some("refs/heads/feature-a=Alpha\nrefs/heads/feature-b\nrefs/heads/feature-c=Gamma\n"),
        &[],
    );
    let json = parse_stdout_json(&output);

    assert_eq!(json["base"], "main");
    assert_eq!(
        json["refs"].as_array().expect("refs should be array").len(),
        3
    );
    assert_eq!(json["refs"][0]["label"], "Alpha");
    assert_eq!(json["refs"][1]["label"], "refs/heads/feature-b");
    assert_eq!(json["refs"][2]["label"], "Gamma");
    assert_eq!(json["merge_order"]["status"], "complete");
    assert_eq!(json["merge_order"]["sequenced"], serde_json::json!([]));
    assert_eq!(
        json["merge_order"]["independent"]
            .as_array()
            .expect("independent")
            .len(),
        3
    );
    assert!(
        json["pairs"]
            .as_array()
            .expect("pairs should be array")
            .iter()
            .all(|pair| pair["score"] == "green"),
        "all disjoint branches should score green: {json}"
    );
    assert_eq!(json["skipped"], serde_json::json!([]));
    assert!(
        !repo.join(".grove").exists(),
        "ci analyze must not create .grove"
    );
}

#[test]
fn ci_analyze_reports_complete_merge_order_for_conflicting_pair() {
    let repo_dir = init_repo();
    let repo = repo_dir.path();

    create_branch(
        repo,
        "small-change",
        &[("src/shared.ts", "export const shared = 2;\n")],
    );
    create_branch(
        repo,
        "large-change",
        &[
            ("src/shared.ts", "export const shared = 3;\n"),
            ("src/b.ts", "export const b = 'large-change';\n"),
        ],
    );

    let output = run_grove(
        repo,
        &[
            "ci",
            "analyze",
            "refs/heads/small-change",
            "refs/heads/large-change",
        ],
        None,
        &[],
    );
    let json = parse_stdout_json(&output);

    assert_eq!(json["merge_order"]["status"], "complete");
    assert_eq!(
        json["merge_order"]["sequenced"],
        serde_json::json!(["refs/heads/small-change", "refs/heads/large-change"])
    );
    assert_eq!(json["merge_order"]["independent"], serde_json::json!([]));
    assert_ne!(json["pairs"][0]["score"], "green");
}

#[test]
fn ci_analyze_reports_cycle_status_when_merge_hints_form_cycle() {
    let repo_dir = init_repo();
    let repo = repo_dir.path();

    create_branch(
        repo,
        "branch-a",
        &[
            (
                "src/api.ts",
                "export function foo(value: string): string {\n  return value.trim();\n}\n",
            ),
            ("src/shared.ts", "export const shared = 2;\n"),
            ("src/a-extra.ts", "export const aExtra = true;\n"),
        ],
    );
    create_branch(
        repo,
        "branch-b",
        &[
            (
                "src/consumer.ts",
                "import { foo } from './api';\nexport function useFoo(): string {\n  return foo('  hi  ');\n}\n",
            ),
            ("src/shared.ts", "export const shared = 3;\n"),
        ],
    );
    create_branch(
        repo,
        "branch-c",
        &[
            ("src/shared.ts", "export const shared = 4;\n"),
            ("src/c-extra.ts", "export const cExtra = true;\n"),
        ],
    );

    let output = run_grove(
        repo,
        &[
            "ci",
            "analyze",
            "refs/heads/branch-a",
            "refs/heads/branch-b",
            "refs/heads/branch-c",
        ],
        None,
        &[],
    );
    let json = parse_stdout_json(&output);

    assert_eq!(json["merge_order"]["status"], "cycle");
    assert!(
        json["merge_order"]["cycle_note"]
            .as_str()
            .map(|note| !note.is_empty())
            .unwrap_or(false),
        "cycle status should include a note: {json}"
    );
}

#[test]
fn ci_analyze_reports_partial_when_a_pair_times_out() {
    let repo_dir = init_repo();
    let repo = repo_dir.path();

    create_branch(
        repo,
        "partial-a",
        &[("src/a.ts", "export const a = 'partial-a';\n")],
    );
    create_branch(
        repo,
        "partial-b",
        &[("src/b.ts", "export const b = 'partial-b';\n")],
    );
    create_branch(
        repo,
        "partial-c",
        &[("src/c.ts", "export const c = 'partial-c';\n")],
    );

    let output = run_grove(
        repo,
        &[
            "ci",
            "analyze",
            "refs/heads/partial-a",
            "refs/heads/partial-b",
            "refs/heads/partial-c",
        ],
        None,
        &[(
            "GROVE_CI_TEST_TIMEOUT_PAIRS",
            "refs/heads/partial-a|refs/heads/partial-b",
        )],
    );
    let json = parse_stdout_json(&output);

    assert_eq!(json["merge_order"]["status"], "partial");
    assert_eq!(
        json["merge_order"]["incomplete_pairs"],
        serde_json::json!([{
            "a": "refs/heads/partial-a",
            "b": "refs/heads/partial-b"
        }])
    );

    let timed_out_pair = json["pairs"]
        .as_array()
        .expect("pairs should be array")
        .iter()
        .find(|pair| pair["a"] == "refs/heads/partial-a" && pair["b"] == "refs/heads/partial-b")
        .expect("timed out pair should exist");
    assert!(timed_out_pair["score"].is_null());
    assert_eq!(timed_out_pair["timed_out"], true);
}

#[test]
fn ci_analyze_reports_unavailable_when_all_pairs_time_out() {
    let repo_dir = init_repo();
    let repo = repo_dir.path();

    create_branch(
        repo,
        "timeout-a",
        &[("src/a.ts", "export const a = 'timeout-a';\n")],
    );
    create_branch(
        repo,
        "timeout-b",
        &[("src/b.ts", "export const b = 'timeout-b';\n")],
    );

    let output = run_grove(
        repo,
        &[
            "ci",
            "analyze",
            "--timeout",
            "0",
            "refs/heads/timeout-a",
            "refs/heads/timeout-b",
        ],
        None,
        &[],
    );
    let json = parse_stdout_json(&output);

    assert_eq!(json["merge_order"]["status"], "unavailable");
    assert_eq!(
        json["merge_order"]["incomplete_pairs"],
        serde_json::json!([{
            "a": "refs/heads/timeout-a",
            "b": "refs/heads/timeout-b"
        }])
    );
    assert!(json["pairs"][0]["score"].is_null());
    assert_eq!(json["pairs"][0]["timed_out"], true);
}
