use dispel::scan::net::ConnectionTracker;

/// A perfect 5-second beacon (4 samples) should be detected with 1-second tolerance.
#[test]
fn test_regular_beacon_detected() {
    let mut tracker = ConnectionTracker::new();
    // Timestamps: 0, 5, 10, 15 → intervals all 5s, std_dev = 0
    tracker.record_connection("10.0.0.1:4444", 0);
    tracker.record_connection("10.0.0.1:4444", 5);
    tracker.record_connection("10.0.0.1:4444", 10);
    tracker.record_connection("10.0.0.1:4444", 15);

    let beacons = tracker.detect_beacons(1.0);
    assert_eq!(beacons.len(), 1, "expected exactly one beacon");
    let b = &beacons[0];
    assert_eq!(b.destination, "10.0.0.1:4444");
    assert!((b.interval_secs - 5.0).abs() < 0.01, "mean interval should be ~5s");
    assert!(b.jitter < 0.01, "jitter should be ~0 for perfectly regular beacon");
    assert_eq!(b.sample_count, 4);
}

/// Irregular traffic (varying intervals) should NOT be flagged with 1-second tolerance.
#[test]
fn test_irregular_traffic_not_flagged() {
    let mut tracker = ConnectionTracker::new();
    // Intervals: 1, 10, 3, 20 → high variance
    tracker.record_connection("10.0.0.2:8080", 0);
    tracker.record_connection("10.0.0.2:8080", 1);
    tracker.record_connection("10.0.0.2:8080", 11);
    tracker.record_connection("10.0.0.2:8080", 14);
    tracker.record_connection("10.0.0.2:8080", 34);

    let beacons = tracker.detect_beacons(1.0);
    assert!(
        beacons.is_empty(),
        "irregular traffic should not be flagged as beacon"
    );
}

/// A beacon with up to ~3s of jitter should be detected with 3-second tolerance.
#[test]
fn test_beacon_with_jitter_detected_with_loose_tolerance() {
    let mut tracker = ConnectionTracker::new();
    // Target interval: 30s with ±1s jitter → intervals: 29, 31, 30, 29 → std_dev < 1
    tracker.record_connection("192.168.1.100:9000", 0);
    tracker.record_connection("192.168.1.100:9000", 29);
    tracker.record_connection("192.168.1.100:9000", 60);
    tracker.record_connection("192.168.1.100:9000", 90);
    tracker.record_connection("192.168.1.100:9000", 119);

    let beacons = tracker.detect_beacons(3.0);
    assert_eq!(beacons.len(), 1, "jittery beacon should be caught with 3s tolerance");
    let b = &beacons[0];
    assert!(b.jitter <= 3.0, "jitter must be within tolerance");
}

/// Fewer than 4 samples should never produce a beacon detection.
#[test]
fn test_minimum_samples_required() {
    let mut tracker = ConnectionTracker::new();
    // Only 2 connections — not enough.
    tracker.record_connection("172.16.0.1:4444", 0);
    tracker.record_connection("172.16.0.1:4444", 5);

    let beacons = tracker.detect_beacons(1.0);
    assert!(
        beacons.is_empty(),
        "2 samples should not be sufficient for beacon detection"
    );
}

/// Exactly 3 samples (one interval pair) should also be insufficient.
#[test]
fn test_three_samples_not_enough() {
    let mut tracker = ConnectionTracker::new();
    tracker.record_connection("172.16.0.1:4444", 0);
    tracker.record_connection("172.16.0.1:4444", 5);
    tracker.record_connection("172.16.0.1:4444", 10);

    let beacons = tracker.detect_beacons(1.0);
    assert!(beacons.is_empty(), "3 samples should not trigger beacon detection");
}
