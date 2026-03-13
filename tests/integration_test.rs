use std::process::Command;

#[test]
fn test_scan_runs_and_produces_json() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run realm-detect");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON output");

    // Should have severity field
    assert!(parsed.get("severity").is_some());
}

#[test]
fn test_scan_proc_layer_only() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--layer", "proc", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run realm-detect");

    // Exit code 0 (clean) or scan completed
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || output.status.success());
}

#[test]
fn test_help_flag() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run realm-detect");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("realm-detect") || stdout.contains("Realm"));
}
