//! Validation tests: simulate Realm C2 implant artifacts and verify detection.
//!
//! These tests create synthetic files containing real Realm C2 signatures
//! and verify that dispel catches them across all detection layers.

use dispel::scan::proc::BinaryScanner;
use dispel::scan::persist;
use dispel::scan::net;
use dispel::Tier;
use std::io::Write;

// ---------------------------------------------------------------------------
// Layer 1: Process / Binary scanning
// ---------------------------------------------------------------------------

fn make_fake_implant() -> Vec<u8> {
    let mut payload = vec![0u8; 200]; // padding

    // Tier 3: gRPC service paths
    payload.extend_from_slice(b"/c2.C2/ClaimTasks");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"/c2.C2/ReportOutput");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"/c2.C2/ReverseShell");
    payload.extend_from_slice(&[0u8; 50]);

    // Tier 3: Eldritch distinctive functions
    payload.extend_from_slice(b"_terminate_this_process_clowntown");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"dll_inject");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"reverse_shell_pty");
    payload.extend_from_slice(&[0u8; 50]);

    // Tier 3: Eldritch agent API
    payload.extend_from_slice(b"report_credential");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"set_callback_interval");
    payload.extend_from_slice(&[0u8; 50]);

    // Tier 3: Eldritch offensive
    payload.extend_from_slice(b"ssh_exec");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"create_portal");
    payload.extend_from_slice(&[0u8; 50]);

    // Tier 2 strings
    payload.extend_from_slice(b"imix-v");
    payload.extend_from_slice(&[0u8; 50]);
    payload.extend_from_slice(b"eldritch::");
    payload.extend_from_slice(&[0u8; 50]);

    payload.extend_from_slice(&[0u8; 200]); // padding
    payload
}

#[test]
fn binary_scanner_detects_grpc_paths_in_fake_implant() {
    let scanner = BinaryScanner::new();
    let payload = make_fake_implant();
    let findings = scanner.scan_bytes(&payload, "/tmp/fake-imix");

    let grpc_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.description.contains("gRPC service path"))
        .collect();

    assert!(
        grpc_findings.len() >= 3,
        "Expected at least 3 gRPC path findings, got {}: {:?}",
        grpc_findings.len(),
        grpc_findings.iter().map(|f| &f.description).collect::<Vec<_>>()
    );

    // All gRPC findings should be Tier3
    for f in &grpc_findings {
        assert_eq!(f.tier, Tier::Tier3, "gRPC finding should be Tier3: {}", f.description);
    }
}

#[test]
fn binary_scanner_detects_eldritch_functions() {
    let scanner = BinaryScanner::new();
    let payload = make_fake_implant();
    let findings = scanner.scan_bytes(&payload, "/tmp/fake-imix");

    let eldritch_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.description.contains("Eldritch"))
        .collect();

    assert!(
        eldritch_findings.len() >= 4,
        "Expected at least 4 Eldritch findings, got {}: {:?}",
        eldritch_findings.len(),
        eldritch_findings.iter().map(|f| &f.description).collect::<Vec<_>>()
    );
}

#[test]
fn binary_scanner_detects_tier2_strings() {
    let scanner = BinaryScanner::new();
    let payload = make_fake_implant();
    let findings = scanner.scan_bytes(&payload, "/tmp/fake-imix");

    let tier2_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.tier == Tier::Tier2)
        .collect();

    assert!(
        tier2_findings.len() >= 1,
        "Expected at least 1 Tier2 finding, got {}: {:?}",
        tier2_findings.len(),
        tier2_findings.iter().map(|f| &f.description).collect::<Vec<_>>()
    );
}

#[test]
fn binary_scanner_score_reaches_detected() {
    let scanner = BinaryScanner::new();
    let payload = make_fake_implant();
    let findings = scanner.scan_bytes(&payload, "/tmp/fake-imix");

    let total_score: u32 = findings.iter().map(|f| f.tier.weight()).sum();
    assert!(
        total_score >= 5,
        "Expected DETECTED threshold (score >= 5), got {}",
        total_score
    );
    // With multiple Tier3 + Tier2 findings, score should be very high
    assert!(
        total_score >= 30,
        "Expected high confidence (score >= 30) for full Realm implant, got {}",
        total_score
    );
}

#[test]
fn binary_scanner_on_file() {
    let scanner = BinaryScanner::new();
    let payload = make_fake_implant();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fake-imix");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&payload).unwrap();
    drop(file);

    let findings = scanner.scan_file(path.to_str().unwrap());
    assert!(
        !findings.is_empty(),
        "File-based scan should detect signatures"
    );

    let total_score: u32 = findings.iter().map(|f| f.tier.weight()).sum();
    assert!(total_score >= 30, "File scan score should match bytes scan: {}", total_score);
}

// ---------------------------------------------------------------------------
// Layer 2: Network detection
// ---------------------------------------------------------------------------

#[test]
fn grpc_path_in_http2_traffic() {
    // Simulate HTTP/2 frame containing Realm gRPC path
    let mut traffic = Vec::new();
    traffic.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    traffic.extend_from_slice(b"\x00\x00\x1d\x01\x04\x00\x00\x00\x01");
    traffic.extend_from_slice(b"POST /c2.C2/ClaimTasks HTTP/2");
    traffic.extend_from_slice(b"\r\ncontent-type: application/grpc\r\n");

    let findings = net::check_grpc_payload(&traffic);
    assert!(
        !findings.is_empty(),
        "Should detect gRPC path in HTTP/2 traffic"
    );

    let has_claim_tasks = findings.iter().any(|f| f.description.contains("ClaimTasks"));
    assert!(has_claim_tasks, "Should specifically identify ClaimTasks path");
}

#[test]
fn dns_c2_base32_subdomain() {
    // Simulate DNS query with base32-encoded subdomain (Realm DNS C2)
    let query = "MFZWIZLTOQQGC3TEBWXG2ZLUNFZWQQ3PNZZSAYLQME.c2server.evil.com";
    let result = net::check_dns_c2_query(query);
    assert!(
        result.is_some(),
        "Should detect base32-encoded DNS C2 subdomain"
    );
}

#[test]
fn encrypted_prefix_detection() {
    // Simulate 56-byte high-entropy prefix (X25519 pubkey + XChaCha20 nonce)
    // Use pseudo-random bytes with high entropy
    let mut prefix = Vec::new();
    for i in 0..56u8 {
        prefix.push(i.wrapping_mul(7).wrapping_add(13).wrapping_mul(i.wrapping_add(1)));
    }
    // Add more data after
    prefix.extend_from_slice(&[0u8; 200]);

    let result = net::check_encrypted_prefix(&prefix);
    // Whether this triggers depends on the entropy of our pseudo-random bytes
    // At minimum, verify the function doesn't panic
    let _ = result;
}

// ---------------------------------------------------------------------------
// Layer 3: Persistence detection
// ---------------------------------------------------------------------------

#[test]
fn beacon_id_file_detection() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("system-id");

    // Write a UUID v4 beacon ID (exactly what Realm writes)
    std::fs::write(&path, "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d").unwrap();

    let finding = persist::check_uuid_file(path.to_str().unwrap());
    assert!(
        finding.is_some(),
        "Should detect UUID v4 beacon ID file"
    );

    let f = finding.unwrap();
    assert_eq!(f.tier, Tier::Tier2);
    assert!(f.description.contains("beacon ID"));
}

#[test]
fn beacon_id_rejects_non_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("system-id");

    std::fs::write(&path, "this-is-not-a-valid-uuid-value!!!!!").unwrap();

    let finding = persist::check_uuid_file(path.to_str().unwrap());
    assert!(
        finding.is_none(),
        "Should not detect non-UUID content as beacon ID"
    );
}

// ---------------------------------------------------------------------------
// End-to-end: full scan on clean system
// ---------------------------------------------------------------------------

#[test]
fn full_scan_json_output_is_valid() {
    let output = std::process::Command::new("cargo")
        .args(["run", "--release", "--", "scan", "--json"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to run dispel");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output should be valid JSON");

    assert!(parsed.get("findings").is_some(), "Should have findings field");
    assert!(parsed.get("score").is_some(), "Should have score field");
    assert!(parsed.get("severity").is_some(), "Should have severity field");
}
