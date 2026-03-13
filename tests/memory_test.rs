use std::process::Command;

/// Verify that `dispel scan --layer memory --json` returns valid JSON
/// with the expected top-level fields.
#[test]
fn test_memory_scan_returns_valid_json() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--layer", "memory", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run dispel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid JSON output from memory scan");

    assert!(result["findings"].is_array(), "findings should be an array");
    assert!(result["score"].is_number(), "score should be a number");
    assert!(result["severity"].is_string(), "severity should be a string");
}

/// Verify that the severity field is one of the expected values.
#[test]
fn test_memory_scan_severity_is_valid() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--layer", "memory", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run dispel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid JSON output");

    let severity = result["severity"].as_str().expect("severity should be a string");
    assert!(
        ["clean", "suspect", "detected"].contains(&severity),
        "unexpected severity value: {}",
        severity
    );
}

/// Verify that each finding in memory scan output has the expected structure
/// and that the layer field is always "memory".
#[test]
fn test_memory_scan_findings_structure() {
    let output = Command::new("cargo")
        .args(["run", "--", "scan", "--layer", "memory", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run dispel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value =
        serde_json::from_str(&stdout).expect("invalid JSON output");

    let findings = result["findings"].as_array().expect("findings should be an array");
    for finding in findings {
        assert!(finding["layer"].is_string(), "finding should have a layer field");
        assert_eq!(
            finding["layer"].as_str().unwrap(),
            "memory",
            "memory-only scan should only produce memory-layer findings"
        );
        assert!(finding["description"].is_string(), "finding should have a description");
        assert!(finding["tier"].is_string(), "finding should have a tier");
        assert!(finding["detail"].is_string(), "finding should have a detail");
    }
}
