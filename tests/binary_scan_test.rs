use dispel::scan::proc::BinaryScanner;
use dispel::Tier;

fn scanner() -> BinaryScanner {
    BinaryScanner::new()
}

#[test]
fn detects_grpc_path_in_bytes() {
    let sc = scanner();
    let data = b"some prefix /c2.C2/ClaimTasks some suffix";
    let findings = sc.scan_bytes(data, "/tmp/test_binary");
    assert!(
        !findings.is_empty(),
        "should detect gRPC path in raw bytes"
    );
    let f = &findings[0];
    assert_eq!(f.tier, Tier::Tier3);
    assert!(f.description.contains("/c2.C2/ClaimTasks"));
}

#[test]
fn detects_eldritch_function_in_bytes() {
    let sc = scanner();
    let data = b"padding _terminate_this_process_clowntown more padding";
    let findings = sc.scan_bytes(data, "/tmp/test_eldritch");
    assert!(
        !findings.is_empty(),
        "should detect eldritch distinctive function"
    );
    assert_eq!(findings[0].tier, Tier::Tier3);
}

#[test]
fn detects_tier2_string_in_bytes() {
    let sc = scanner();
    let data = b"binary data eldritch:: more data";
    let findings = sc.scan_bytes(data, "/tmp/test_tier2");
    assert!(!findings.is_empty(), "should detect tier2 string");
    assert_eq!(findings[0].tier, Tier::Tier2);
}

#[test]
fn no_false_positive_on_clean_binary() {
    let sc = scanner();
    let data = b"hello world this is a totally benign binary with no c2 indicators";
    let findings = sc.scan_bytes(data, "/tmp/clean_binary");
    assert!(findings.is_empty(), "should have no findings in clean data");
}

#[test]
fn deduplicates_repeated_pattern() {
    let sc = scanner();
    // The same gRPC path appears twice
    let data =
        b"/c2.C2/ClaimTasks some data in the middle /c2.C2/ClaimTasks end";
    let findings = sc.scan_bytes(data, "/tmp/dup_binary");

    let count = findings
        .iter()
        .filter(|f| f.description.contains("/c2.C2/ClaimTasks"))
        .count();
    assert_eq!(count, 1, "duplicate pattern should be deduplicated to one finding");
}

#[test]
fn finds_multiple_distinct_patterns() {
    let sc = scanner();
    // Include a gRPC path, an eldritch distinctive function, and a tier2 string
    let data = b"/c2.C2/FetchAsset padding dll_inject more padding imix::";
    let findings = sc.scan_bytes(data, "/tmp/multi_pattern");

    // Should have at least 3 distinct findings
    assert!(
        findings.len() >= 3,
        "should detect multiple distinct patterns, got: {:?}",
        findings.iter().map(|f| &f.description).collect::<Vec<_>>()
    );
}

#[test]
fn scan_file_returns_empty_for_missing_file() {
    let sc = scanner();
    let findings = sc.scan_file("/nonexistent/path/that/does/not/exist");
    assert!(findings.is_empty(), "missing file should yield no findings");
}

#[test]
fn scan_file_works_on_real_file() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let sc = scanner();
    let mut tf = NamedTempFile::new().unwrap();
    tf.write_all(b"/c2.C2/ClaimTasks some binary content here").unwrap();
    tf.flush().unwrap();

    let path = tf.path().to_str().unwrap().to_string();
    let findings = sc.scan_file(&path);
    assert!(!findings.is_empty(), "should detect pattern in temp file");
}
