use dispel::{Finding, ScanResult, Severity, Tier};

fn make_finding(tier: Tier) -> Finding {
    Finding::new("test", "test finding", tier, "detail")
}

#[test]
fn test_empty_result_is_clean() {
    let result = ScanResult::new();
    assert_eq!(result.score, 0);
    assert_eq!(result.severity, Severity::Clean);
    assert_eq!(result.exit_code(), 0);
    assert!(result.findings.is_empty());
}

#[test]
fn test_tier1_alone_is_suspect() {
    let mut result = ScanResult::new();
    result.add_finding(make_finding(Tier::Tier1)); // weight 1
    assert_eq!(result.score, 1);
    assert_eq!(result.severity, Severity::Suspect);
    assert_eq!(result.exit_code(), 1);
}

#[test]
fn test_tier3_alone_is_detected() {
    let mut result = ScanResult::new();
    result.add_finding(make_finding(Tier::Tier3)); // weight 5
    assert_eq!(result.score, 5);
    assert_eq!(result.severity, Severity::Detected);
    assert_eq!(result.exit_code(), 2);
}

#[test]
fn test_compound_scoring() {
    let mut result = ScanResult::new();
    // T1(1) + T2(3) = 4 => suspect
    result.add_finding(make_finding(Tier::Tier1));
    result.add_finding(make_finding(Tier::Tier2));
    assert_eq!(result.score, 4);
    assert_eq!(result.severity, Severity::Suspect);

    // adding another T1(1) pushes to 5 => detected
    result.add_finding(make_finding(Tier::Tier1));
    assert_eq!(result.score, 5);
    assert_eq!(result.severity, Severity::Detected);
}

#[test]
fn test_behavioral_weight() {
    let mut result = ScanResult::new();
    result.add_finding(make_finding(Tier::Behavioral)); // weight 4
    assert_eq!(result.score, 4);
    assert_eq!(result.severity, Severity::Suspect);

    // One more tier1 pushes it over the threshold
    result.add_finding(make_finding(Tier::Tier1));
    assert_eq!(result.score, 5);
    assert_eq!(result.severity, Severity::Detected);
}

#[test]
fn test_dedup_key() {
    let f = Finding::new("proc", "imix binary found", Tier::Tier1, "/tmp/imix");
    assert_eq!(f.dedup_key(), "proc:imix binary found");

    let f2 = Finding::new("persist", "imix binary found", Tier::Tier1, "/bin/imix");
    // Same description but different layer => different key
    assert_ne!(f.dedup_key(), f2.dedup_key());
}

#[test]
fn test_json_serialization() {
    let mut result = ScanResult::new();
    result.add_finding(Finding::new("proc", "test", Tier::Tier2, "detail"));

    let json = serde_json::to_string(&result).expect("serialization failed");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

    assert_eq!(parsed["severity"], "suspect");
    assert_eq!(parsed["score"], 3);
    assert!(parsed["findings"].is_array());
    assert_eq!(parsed["findings"][0]["tier"], "tier2");
    assert_eq!(parsed["findings"][0]["layer"], "proc");
}

#[test]
fn test_merge() {
    let mut a = ScanResult::new();
    a.add_finding(make_finding(Tier::Tier2)); // score 3

    let mut b = ScanResult::new();
    b.add_finding(make_finding(Tier::Tier2)); // score 3

    a.merge(b);
    assert_eq!(a.score, 6);
    assert_eq!(a.findings.len(), 2);
    assert_eq!(a.severity, Severity::Detected);
}
