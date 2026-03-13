use dispel::{Finding, ScanResult, Tier};

#[test]
fn test_json_output_structure() {
    let mut result = ScanResult::new();
    result.add_finding(Finding::new(
        "proc",
        "imix binary found",
        Tier::Tier3,
        "/tmp/imix",
    ));

    let json = serde_json::to_string_pretty(&result).expect("should serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("should parse");

    assert!(v["findings"].is_array());
    assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    assert_eq!(v["severity"], "detected");
    assert_eq!(v["score"], 5);

    let finding = &v["findings"][0];
    assert_eq!(finding["layer"], "proc");
    assert_eq!(finding["description"], "imix binary found");
    assert_eq!(finding["tier"], "tier3");
    assert_eq!(finding["detail"], "/tmp/imix");
}

#[test]
fn test_json_output_clean_result() {
    let result = ScanResult::new();
    let json = serde_json::to_string(&result).expect("should serialize");
    let v: serde_json::Value = serde_json::from_str(&json).expect("should parse");

    assert_eq!(v["severity"], "clean");
    assert_eq!(v["score"], 0);
    assert_eq!(v["findings"].as_array().unwrap().len(), 0);
}
