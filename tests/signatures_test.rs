use realm_detect::signatures::strings::{
    GRPC_PATHS, ELDRITCH_DISTINCTIVE, ELDRITCH_AGENT_API,
    TIER2_STRINGS, TIER1_BINARY_NAMES, TIER1_SERVICE_NAMES,
    TIER1_INSTALL_PATHS_LINUX, all_signatures,
};
use realm_detect::Tier;

#[test]
fn test_grpc_paths_count() {
    assert_eq!(GRPC_PATHS.len(), 8, "Expected 8 gRPC paths");
    assert!(GRPC_PATHS.contains(&"/c2.C2/ClaimTasks"));
    assert!(GRPC_PATHS.contains(&"/c2.C2/CreatePortal"));
}

#[test]
fn test_eldritch_distinctive_contains_clowntown() {
    assert!(
        ELDRITCH_DISTINCTIVE.contains(&"_terminate_this_process_clowntown"),
        "Clowntown string must be present"
    );
    assert!(ELDRITCH_DISTINCTIVE.contains(&"dll_inject"));
    assert!(ELDRITCH_DISTINCTIVE.contains(&"reverse_shell_pty"));
}

#[test]
fn test_eldritch_agent_api_completeness() {
    let expected = &[
        "report_credential",
        "report_process_list",
        "claim_tasks",
        "fetch_asset",
        "get_callback_interval",
        "set_callback_interval",
        "set_callback_uri",
        "list_transports",
        "get_transport",
        "list_tasks",
        "stop_task",
        "get_config",
    ];
    for s in expected {
        assert!(
            ELDRITCH_AGENT_API.contains(s),
            "Missing agent API string: {s}"
        );
    }
}

#[test]
fn test_tier2_strings_present() {
    assert!(TIER2_STRINGS.contains(&"imix-v"));
    assert!(TIER2_STRINGS.contains(&"eldritch::"));
    assert!(TIER2_STRINGS.contains(&"ChachaCodec"));
    assert!(TIER2_STRINGS.contains(&"DnsPacket"));
}

#[test]
fn test_tier1_constants() {
    assert!(TIER1_BINARY_NAMES.contains(&"imix"));
    assert!(TIER1_BINARY_NAMES.contains(&"imix.exe"));
    assert!(TIER1_SERVICE_NAMES.contains(&"imix"));
    assert!(TIER1_SERVICE_NAMES.contains(&"Imix C2 Agent"));
    assert!(TIER1_INSTALL_PATHS_LINUX.contains(&"/tmp/imix"));
    assert!(TIER1_INSTALL_PATHS_LINUX.contains(&"/bin/imix"));
}

#[test]
fn test_all_signatures_tiers() {
    let sigs = all_signatures();

    // Must be non-empty
    assert!(!sigs.is_empty(), "all_signatures() returned empty list");

    // gRPC paths should be Tier3
    let grpc_sigs: Vec<_> = sigs.iter().filter(|(s, _)| s.starts_with("/c2.C2/")).collect();
    assert_eq!(grpc_sigs.len(), GRPC_PATHS.len());
    for (_, tier) in &grpc_sigs {
        assert_eq!(*tier, Tier::Tier3, "gRPC path should be Tier3");
    }

    // TIER2_STRINGS should map to Tier2
    let tier2_sigs: Vec<_> = sigs
        .iter()
        .filter(|(s, t)| *t == Tier::Tier2 && TIER2_STRINGS.contains(s))
        .collect();
    assert_eq!(
        tier2_sigs.len(),
        TIER2_STRINGS.len(),
        "All TIER2_STRINGS should appear as Tier2"
    );

    // Binary names should be Tier1
    for name in TIER1_BINARY_NAMES {
        let found = sigs.iter().any(|(s, t)| s == name && *t == Tier::Tier1);
        assert!(found, "Binary name {name} not found as Tier1");
    }
}
