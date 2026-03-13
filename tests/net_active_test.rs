use realm_detect::scan::net::{check_grpc_payload, check_dns_c2_query, check_encrypted_prefix};
use realm_detect::Tier;

// --- gRPC payload tests ---

/// Payload containing a known Realm C2 gRPC path should generate a Tier3 finding.
#[test]
fn test_grpc_path_detected_in_payload() {
    let payload = b"POST /c2.C2/ClaimTasks HTTP/2\r\ncontent-type: application/grpc\r\n\r\n";
    let findings = check_grpc_payload(payload);

    let grpc_path_finding = findings
        .iter()
        .find(|f| f.detail.contains("/c2.C2/ClaimTasks"));
    assert!(
        grpc_path_finding.is_some(),
        "expected finding for /c2.C2/ClaimTasks"
    );
    assert_eq!(grpc_path_finding.unwrap().tier, Tier::Tier3);
}

/// Normal HTTP traffic (no Realm gRPC paths) should produce no findings.
#[test]
fn test_no_match_on_normal_http_traffic() {
    let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let findings = check_grpc_payload(payload);
    assert!(
        findings.is_empty(),
        "normal HTTP traffic should produce no findings"
    );
}

/// application/grpc content-type over HTTP/1.1 should be flagged at Tier3
/// (gRPC normally runs over HTTP/2; HTTP/1.1 usage is anomalous).
#[test]
fn test_grpc_content_type_over_http11_is_tier3() {
    let payload = b"POST /some/path HTTP/1.1\r\ncontent-type: application/grpc\r\n\r\n";
    let findings = check_grpc_payload(payload);

    let ct_finding = findings
        .iter()
        .find(|f| f.detail.contains("application/grpc"));
    assert!(ct_finding.is_some(), "expected finding for application/grpc content-type");
    assert_eq!(
        ct_finding.unwrap().tier,
        Tier::Tier3,
        "application/grpc over HTTP/1.1 should be Tier3"
    );
}

// --- DNS C2 query tests ---

/// A long base32-encoded subdomain label should be flagged as DNS C2.
#[test]
fn test_dns_long_base32_label_flagged() {
    // 32 uppercase base32 chars (A-Z, 2-7) — well over the 30-char threshold.
    let query = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD.c2.example.com";
    let result = check_dns_c2_query(query);
    assert!(
        result.is_some(),
        "long base32 subdomain should be flagged as DNS C2"
    );
    let desc = result.unwrap();
    assert!(desc.contains("base32"), "description should mention base32");
}

/// A normal short domain label should NOT be flagged.
#[test]
fn test_normal_domain_not_flagged() {
    let query = "www.google.com";
    assert!(
        check_dns_c2_query(query).is_none(),
        "normal domain should not be flagged"
    );
}

/// A short base32-looking label (< 30 chars) should NOT be flagged.
#[test]
fn test_short_base32_label_not_flagged() {
    // Only 10 chars — below the 30-char threshold.
    let query = "ABCDEF2345.example.com";
    assert!(
        check_dns_c2_query(query).is_none(),
        "short label should not be flagged even if it looks like base32"
    );
}

/// A label with lowercase letters is not valid base32 and should not be flagged.
#[test]
fn test_lowercase_label_not_base32() {
    let query = "aaaaaaaaabbbbbbbbccccccccdddddddd.example.com";
    assert!(
        check_dns_c2_query(query).is_none(),
        "lowercase label should not be treated as base32"
    );
}

// --- Encrypted prefix / high-entropy prefix tests ---

/// 56 bytes of near-random data (high entropy) should yield a Tier3 finding.
///
/// The maximum possible Shannon entropy for 56 bytes is log2(56) ≈ 5.807 (all values unique).
/// We construct exactly that: 56 distinct byte values (0..56), each appearing once.
#[test]
fn test_high_entropy_prefix_detected() {
    // 56 unique byte values → entropy = log2(56) ≈ 5.807, well above the 5.4 threshold.
    let data: Vec<u8> = (0u8..56).collect();
    let finding = check_encrypted_prefix(&data);
    assert!(
        finding.is_some(),
        "high-entropy 56-byte prefix should produce a Tier3 finding"
    );
    assert_eq!(finding.unwrap().tier, Tier::Tier3);
}

/// Fewer than 56 bytes should produce no finding regardless of content.
#[test]
fn test_too_short_prefix_no_finding() {
    let data = vec![0xFFu8; 55];
    assert!(
        check_encrypted_prefix(&data).is_none(),
        "fewer than 56 bytes should not produce a finding"
    );
}

/// All-zero data has zero entropy and should NOT be flagged.
#[test]
fn test_low_entropy_prefix_not_flagged() {
    let data = vec![0u8; 56];
    assert!(
        check_encrypted_prefix(&data).is_none(),
        "all-zero data has zero entropy and must not be flagged"
    );
}
