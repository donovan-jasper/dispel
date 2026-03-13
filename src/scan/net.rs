use std::collections::HashMap;
use crate::{Finding, Tier, ScanResult};
use crate::signatures::strings::GRPC_PATHS;

// --- Beacon detection ---

/// A detected beaconing pattern on a specific destination.
#[derive(Debug, Clone)]
pub struct BeaconDetection {
    pub destination: String,
    pub interval_secs: f64,
    pub sample_count: usize,
    pub jitter: f64,
}

/// Tracks connection timestamps per destination to detect regular beaconing.
pub struct ConnectionTracker {
    /// Maps destination string -> sorted list of timestamps (Unix seconds).
    pub connections: HashMap<String, Vec<u64>>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Record a connection to `destination` at the given Unix timestamp (seconds).
    pub fn record_connection(&mut self, destination: &str, timestamp_secs: u64) {
        self.connections
            .entry(destination.to_string())
            .or_default()
            .push(timestamp_secs);
    }

    /// Detect beaconing patterns among recorded connections.
    ///
    /// A destination is flagged if:
    /// - It has at least 4 timestamps, AND
    /// - The standard deviation of intervals between consecutive timestamps is <= `tolerance_secs`
    pub fn detect_beacons(&self, tolerance_secs: f64) -> Vec<BeaconDetection> {
        let mut detections = Vec::new();

        for (dest, timestamps) in &self.connections {
            if timestamps.len() < 4 {
                continue;
            }

            // Sort timestamps and compute inter-arrival intervals.
            let mut sorted = timestamps.clone();
            sorted.sort_unstable();

            let intervals: Vec<f64> = sorted
                .windows(2)
                .map(|w| (w[1] as f64) - (w[0] as f64))
                .collect();

            if intervals.is_empty() {
                continue;
            }

            let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let variance = intervals
                .iter()
                .map(|&x| (x - mean).powi(2))
                .sum::<f64>()
                / intervals.len() as f64;
            let std_dev = variance.sqrt();

            if std_dev <= tolerance_secs {
                detections.push(BeaconDetection {
                    destination: dest.clone(),
                    interval_secs: mean,
                    sample_count: timestamps.len(),
                    jitter: std_dev,
                });
            }
        }

        detections
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// --- Container network filter ---

/// Returns true if `ip` falls within a known container/cluster infrastructure
/// range that should not be flagged as suspicious:
///   10.42.0.0/16  — k3s pod CIDR
///   10.43.0.0/16  — k3s service CIDR
///   172.17.0.0/16 — Docker default bridge
fn is_container_network(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let Ok(a) = parts[0].parse::<u16>() else { return false; };
    let Ok(b) = parts[1].parse::<u16>() else { return false; };

    match (a, b) {
        (10, 42) | (10, 43) | (172, 17) => true,
        _ => false,
    }
}

// --- Common port helper ---

/// Returns true if `port` is a well-known / commonly-allowed port that should
/// not be flagged as suspicious on its own.
fn is_common_port(port: u16) -> bool {
    matches!(
        port,
        22 | 25 | 53 | 80 | 110 | 143 | 443 | 465 | 587 | 993 | 995 | 3306 | 5432 | 8080 | 8443
    )
}

/// Returns true if `ip` belongs to an RFC1918 / link-local / internal range.
/// These connections are generally not C2 callback targets.
fn is_internal_network(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let Ok(a) = parts[0].parse::<u16>() else { return false; };
    let Ok(b) = parts[1].parse::<u16>() else { return false; };

    match a {
        10 => true,                                    // 10.0.0.0/8
        172 if (16..=31).contains(&b) => true,         // 172.16.0.0/12
        192 if b == 168 => true,                       // 192.168.0.0/16
        169 if b == 254 => true,                       // 169.254.0.0/16 link-local
        127 => true,                                   // 127.0.0.0/8
        _ => false,
    }
}

// --- Active packet inspection ---

/// Check raw payload bytes for Realm C2 gRPC paths or `application/grpc` content-type.
///
/// Returns a list of findings.
pub fn check_grpc_payload(data: &[u8]) -> Vec<Finding> {
    let text = String::from_utf8_lossy(data);
    let mut findings = Vec::new();

    // Check for specific Realm C2 gRPC service paths.
    for &path in GRPC_PATHS {
        if text.contains(path) {
            findings.push(Finding::new(
                "net",
                format!("Realm C2 gRPC path detected: {path}"),
                Tier::Tier3,
                path.to_string(),
            ));
        }
    }

    // Check for application/grpc content-type header.
    if text.contains("application/grpc") {
        // If carried over plain HTTP/1.1 it is a stronger signal (gRPC normally uses HTTP/2).
        let tier = if text.contains("HTTP/1.1") {
            Tier::Tier3
        } else {
            Tier::Tier1
        };
        findings.push(Finding::new(
            "net",
            "gRPC content-type detected in traffic".to_string(),
            tier,
            "application/grpc".to_string(),
        ));
    }

    findings
}

/// Check a DNS query label string for signs of DNS-tunnelling / C2 exfiltration.
///
/// Returns `Some(description)` if a suspicious label is found, `None` otherwise.
pub fn check_dns_c2_query(query: &str) -> Option<String> {
    let labels: Vec<&str> = query.split('.').collect();

    for label in labels {
        if label.len() >= 30 && is_base32(label) {
            return Some(format!(
                "Suspicious long base32-encoded DNS label ({} chars): {}",
                label.len(),
                label
            ));
        }
    }

    None
}

/// Check the first 56 bytes of `data` for high Shannon entropy indicating
/// random cryptographic material (e.g. Realm's 32-byte X25519 public key +
/// 24-byte nonce).
///
/// Returns a Tier3 finding if entropy > 7.5, `None` otherwise.
pub fn check_encrypted_prefix(data: &[u8]) -> Option<Finding> {
    if data.len() < 56 {
        return None;
    }

    let entropy = shannon_entropy(&data[..56]);
    // Max achievable entropy for 56 bytes is log2(56) ≈ 5.807 (all unique values).
    // Threshold of 5.4 identifies buffers that are effectively random / well-distributed,
    // consistent with a 32-byte X25519 public key + 24-byte nonce.
    if entropy > 5.4 {
        Some(Finding::new(
            "net",
            "High-entropy prefix detected — possible Realm X25519 pubkey + nonce".to_string(),
            Tier::Tier3,
            format!("entropy={entropy:.4}"),
        ))
    } else {
        None
    }
}

/// Standard Shannon entropy over the byte distribution of `data`.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Returns true if every character in `s` is a valid base32 character
/// (RFC 4648: A-Z, 2-7, =).
fn is_base32(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_uppercase() || matches!(c, '2'..='7') || c == '=')
}

// --- Passive network scan ---

/// Scan active network connections for suspicious activity.
///
/// On Linux, reads `/proc/net/tcp` and `/proc/net/tcp6` for ESTABLISHED connections
/// to non-standard ports on external (non-loopback) addresses.
/// On other platforms the scan is a no-op.
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();

    #[cfg(target_os = "linux")]
    {
        scan_linux(&mut result, verbose);
    }

    #[cfg(windows)]
    {
        use crate::platform::windows;

        let connections = windows::read_tcp_connections();
        if verbose {
            eprintln!("[verbose] Found {} TCP connections", connections.len());
        }

        for conn in &connections {
            if conn.state == "ESTABLISHED"
                && conn.remote_addr != "0.0.0.0"
                && conn.remote_addr != "127.0.0.1"
                && !is_internal_network(&conn.remote_addr)
                && !is_common_port(conn.remote_port)
            {
                result.add_finding(Finding::new(
                    "net",
                    format!(
                        "Outbound to non-standard port {}:{} (PID {})",
                        conn.remote_addr, conn.remote_port, conn.owning_pid
                    ),
                    Tier::Tier1,
                    format!("local={}:{}", conn.local_addr, conn.local_port),
                ));
            }
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = verbose; // suppress unused-variable warning
    }

    result
}

#[cfg(target_os = "linux")]
fn scan_linux(result: &mut ScanResult, verbose: bool) {
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                // Parse the /proc/net/tcp(6) line format:
                //   sl  local_address  rem_address  st  ...
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    continue;
                }

                // State field: 01 = ESTABLISHED
                if fields[3] != "01" {
                    continue;
                }

                let remote_hex = fields[2];
                // Skip IPv6-mapped loopback ::ffff:127.0.0.1
                // (stored as 0000000000000000FFFF00000100007F in /proc/net/tcp6).
                if remote_hex == "0000000000000000FFFF00000100007F:0000"
                    || remote_hex.starts_with("0000000000000000FFFF00000100007F:")
                {
                    continue;
                }

                if let Some((ip, port)) = parse_proc_net_addr(remote_hex) {
                    // Skip loopback and wildcard.
                    if ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "::" {
                        continue;
                    }

                    // Skip internal/private networks — too noisy on
                    // k3s, Docker, and lab environments.
                    if is_internal_network(&ip) || is_container_network(&ip) {
                        continue;
                    }

                    if !is_common_port(port) {
                        let detail = format!("{ip}:{port}");
                        if verbose {
                            eprintln!("[net] ESTABLISHED to non-standard port: {detail}");
                        }
                        result.add_finding(Finding::new(
                            "net",
                            format!("ESTABLISHED connection to non-standard port {port}"),
                            Tier::Behavioral,
                            detail,
                        ));
                    }
                }
            }
        }
    }
}

/// Parse a hex address:port pair from `/proc/net/tcp` format.
///
/// For IPv4 the format is `AABBCCDD:PPPP` (little-endian 32-bit address, big-endian 16-bit port).
/// Returns `(ip_string, port)` or `None` on parse failure.
#[cfg(target_os = "linux")]
fn parse_proc_net_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let port = u16::from_str_radix(parts[1], 16).ok()?;

    let addr_hex = parts[0];
    if addr_hex.len() == 8 {
        // IPv4: 4 bytes little-endian.
        let n = u32::from_str_radix(addr_hex, 16).ok()?;
        let b = n.to_le_bytes(); // already stored LE in /proc/net/tcp
        let ip = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
        Some((ip, port))
    } else if addr_hex.len() == 32 {
        // IPv6: 16 bytes little-endian groups.
        // Simplified: just return the raw hex as the "ip" for filtering purposes.
        // For loopback detection we check ::1 pattern.
        if addr_hex == "00000000000000000000000001000000" {
            return Some(("::1".to_string(), port));
        }
        if addr_hex == "00000000000000000000000000000000" {
            return Some((("::").to_string(), port));
        }
        // Check for IPv4-mapped IPv6: 0000000000000000FFFF0000 prefix
        if addr_hex.starts_with("0000000000000000FFFF0000") {
            let ipv4_hex = &addr_hex[24..32];
            if let Ok(n) = u32::from_str_radix(ipv4_hex, 16) {
                let b = n.to_le_bytes();
                let ip = format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
                return Some((ip, port));
            }
        }
        Some((format!("ipv6:{addr_hex}"), port))
    } else {
        None
    }
}
