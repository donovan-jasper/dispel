use realm_detect::scan::persist::{check_uuid_file, is_uuid_v4};
use std::io::Write;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// is_uuid_v4
// ---------------------------------------------------------------------------

#[test]
fn test_valid_uuid_v4_lowercase() {
    assert!(is_uuid_v4("550e8400-e29b-41d4-a716-446655440000"));
}

#[test]
fn test_valid_uuid_v4_uppercase() {
    assert!(is_uuid_v4("550E8400-E29B-41D4-A716-446655440000"));
}

#[test]
fn test_valid_uuid_v4_mixed_case() {
    assert!(is_uuid_v4("6ba7b810-9dad-41d1-80b4-00c04fd430c8"));
}

#[test]
fn test_valid_uuid_v4_variant_9() {
    // Variant byte can be 8, 9, a, b
    assert!(is_uuid_v4("6ba7b810-9dad-4111-90b4-00c04fd430c8"));
}

#[test]
fn test_valid_uuid_v4_variant_a() {
    assert!(is_uuid_v4("6ba7b810-9dad-4111-a0b4-00c04fd430c8"));
}

#[test]
fn test_valid_uuid_v4_variant_b() {
    assert!(is_uuid_v4("6ba7b810-9dad-4111-b0b4-00c04fd430c8"));
}

#[test]
fn test_invalid_uuid_v1_version() {
    // Version digit is 1, not 4
    assert!(!is_uuid_v4("550e8400-e29b-11d4-a716-446655440000"));
}

#[test]
fn test_invalid_uuid_wrong_variant() {
    // Variant byte is '7' — not in [89ab]
    assert!(!is_uuid_v4("550e8400-e29b-41d4-7716-446655440000"));
}

#[test]
fn test_invalid_uuid_empty_string() {
    assert!(!is_uuid_v4(""));
}

#[test]
fn test_invalid_uuid_garbage() {
    assert!(!is_uuid_v4("not-a-uuid-at-all"));
}

#[test]
fn test_invalid_uuid_too_short() {
    assert!(!is_uuid_v4("550e8400-e29b-41d4-a716-44665544000"));
}

#[test]
fn test_invalid_uuid_too_long() {
    assert!(!is_uuid_v4("550e8400-e29b-41d4-a716-4466554400000"));
}

#[test]
fn test_invalid_uuid_no_dashes() {
    assert!(!is_uuid_v4("550e8400e29b41d4a716446655440000"));
}

// ---------------------------------------------------------------------------
// check_uuid_file
// ---------------------------------------------------------------------------

#[test]
fn test_uuid_file_valid_detection() {
    let mut f = NamedTempFile::new().expect("tempfile");
    write!(f, "550e8400-e29b-41d4-a716-446655440000").expect("write");
    let path = f.path().to_str().expect("path");

    let finding = check_uuid_file(path);
    assert!(finding.is_some(), "expected a finding for valid UUID file");

    let finding = finding.unwrap();
    assert_eq!(finding.layer, "persist");
    assert_eq!(finding.tier, realm_detect::Tier::Tier2);
    assert!(finding.detail.contains("550e8400-e29b-41d4-a716-446655440000"));
}

#[test]
fn test_uuid_file_with_trailing_newline() {
    let mut f = NamedTempFile::new().expect("tempfile");
    writeln!(f, "550e8400-e29b-41d4-a716-446655440000").expect("write");
    let path = f.path().to_str().expect("path");

    // Should still detect: trim() strips the newline before length check.
    let finding = check_uuid_file(path);
    assert!(finding.is_some());
}

#[test]
fn test_uuid_file_wrong_content_rejected() {
    let mut f = NamedTempFile::new().expect("tempfile");
    write!(f, "this-is-not-a-valid-uuid-v4-string!!").expect("write");
    let path = f.path().to_str().expect("path");

    let finding = check_uuid_file(path);
    assert!(finding.is_none(), "non-UUID content should not produce a finding");
}

#[test]
fn test_uuid_file_wrong_size_rejected() {
    let mut f = NamedTempFile::new().expect("tempfile");
    write!(f, "tooshort").expect("write");
    let path = f.path().to_str().expect("path");

    let finding = check_uuid_file(path);
    assert!(finding.is_none(), "short file should not produce a finding");
}

#[test]
fn test_uuid_file_nonexistent_returns_none() {
    let finding = check_uuid_file("/nonexistent/path/that/does/not/exist");
    assert!(finding.is_none());
}

#[test]
fn test_uuid_file_v1_uuid_rejected() {
    // 35-character v1 UUID (wrong version digit)
    let mut f = NamedTempFile::new().expect("tempfile");
    write!(f, "550e8400-e29b-11d4-a716-446655440000").expect("write");
    let path = f.path().to_str().expect("path");

    let finding = check_uuid_file(path);
    assert!(finding.is_none(), "UUID v1 should not match UUID v4 check");
}
