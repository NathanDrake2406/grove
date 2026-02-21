use std::process::Command;

#[test]
fn json_flag_emits_structured_error_on_command_failure() {
    let temp_dir = tempfile::tempdir().expect("temp dir should be created");

    let output = Command::new(env!("CARGO_BIN_EXE_grove"))
        .args(["--json", "daemon", "stop"])
        .current_dir(temp_dir.path())
        .output()
        .expect("grove binary should run");

    assert!(
        !output.status.success(),
        "daemon stop outside workspace should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    let json_line = stderr
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .expect("stderr should contain output");

    let value: serde_json::Value = serde_json::from_str(json_line)
        .unwrap_or_else(|_| panic!("stderr should be JSON; got: {stderr}"));

    assert_eq!(value["ok"], false);
    assert!(
        value["error"]
            .as_str()
            .map(|error| !error.is_empty())
            .unwrap_or(false),
        "json error field should be a non-empty string"
    );
}
