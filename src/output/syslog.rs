//! Syslog (CEF) and webhook output for dispel findings.
//!
//! - `format_syslog_line` formats a finding as a CEF string.
//! - `send_to_syslog` sends a CEF line to local syslog via UDP 127.0.0.1:514.
//! - `send_to_webhook` POSTs a finding as JSON to a webhook URL via raw TCP.

use crate::{Finding, Tier};
use std::io::Write;
use std::net::UdpSocket;

/// Map tier to CEF severity (0-10 scale).
fn cef_severity(tier: &Tier) -> u8 {
    match tier {
        Tier::Tier3 => 10,
        Tier::Behavioral => 7,
        Tier::Tier2 => 5,
        Tier::Tier1 => 3,
    }
}

/// Format a finding as a CEF (Common Event Format) syslog line.
///
/// Format: `CEF:0|dispel|dispel|0.1.0|<tier>|<description>|<severity>|src=<detail>`
pub fn format_syslog_line(finding: &Finding) -> String {
    let severity = cef_severity(&finding.tier);
    // Escape pipes in description and detail per CEF spec
    let desc = finding.description.replace('\\', "\\\\").replace('|', "\\|");
    let detail = finding.detail.replace('\\', "\\\\").replace('=', "\\=");
    format!(
        "CEF:0|dispel|dispel|0.1.0|{}|{}|{}|src={}",
        finding.tier.label(),
        desc,
        severity,
        detail,
    )
}

/// Send a finding to local syslog via UDP to 127.0.0.1:514.
/// Best-effort: silently ignores errors (syslog may not be running).
pub fn send_to_syslog(finding: &Finding) {
    let line = format_syslog_line(finding);
    // Wrap in syslog RFC 3164 format: <priority>message
    // facility=1 (user-level), severity from CEF mapping
    // Using facility=1 (user), severity=6 (info) -> priority = 1*8+6 = 14
    let msg = format!("<14>{}", line);

    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        let _ = socket.send_to(msg.as_bytes(), "127.0.0.1:514");
    }
}

/// Send a finding as JSON to a webhook URL via raw HTTP POST over TCP.
/// Best-effort: silently ignores errors (webhook may not be reachable).
///
/// Expects `url` in the form `http://host:port/path` or `http://host/path`.
pub fn send_to_webhook(finding: &Finding, url: &str) {
    let json_body = match serde_json::to_string(finding) {
        Ok(j) => j,
        Err(_) => return,
    };

    // Parse URL: extract host, port, path
    let (host, port, path) = match parse_http_url(url) {
        Some(v) => v,
        None => return,
    };

    let addr = format!("{}:{}", host, port);
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path, host, json_body.len(), json_body,
    );

    // Connect with a short timeout to avoid blocking the scan loop
    let sock_addr: std::net::SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => {
            // Try DNS resolution
            use std::net::ToSocketAddrs;
            match addr.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(a) => a,
                    None => return,
                },
                Err(_) => return,
            }
        }
    };

    let stream = match std::net::TcpStream::connect_timeout(
        &sock_addr,
        std::time::Duration::from_secs(5),
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
    let mut writer = std::io::BufWriter::new(stream);
    let _ = writer.write_all(request.as_bytes());
    let _ = writer.flush();
}

/// Parse a simple HTTP URL into (host, port, path).
/// Only supports `http://` (not https).
fn parse_http_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rfind(':') {
        Some(i) => {
            let port: u16 = authority[i + 1..].parse().ok()?;
            (&authority[..i], port)
        }
        None => (authority, 80),
    };

    Some((host.to_string(), port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Tier};

    #[test]
    fn test_format_syslog_line() {
        let finding = Finding::new("proc", "test description", Tier::Tier1, "path=/tmp/imix");
        let line = format_syslog_line(&finding);
        assert!(line.starts_with("CEF:0|dispel|dispel|0.1.0|T1|"));
        assert!(line.contains("test description"));
        assert!(line.contains("|3|"));
        assert!(line.contains("src=path\\=/tmp/imix"));
    }

    #[test]
    fn test_cef_severity_mapping() {
        assert_eq!(cef_severity(&Tier::Tier3), 10);
        assert_eq!(cef_severity(&Tier::Behavioral), 7);
        assert_eq!(cef_severity(&Tier::Tier2), 5);
        assert_eq!(cef_severity(&Tier::Tier1), 3);
    }

    #[test]
    fn test_parse_http_url() {
        let (h, p, path) = parse_http_url("http://example.com:8080/hook").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/hook");

        let (h, p, path) = parse_http_url("http://10.0.0.1/alerts").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 80);
        assert_eq!(path, "/alerts");

        let (h, p, path) = parse_http_url("http://10.0.0.1:9000").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 9000);
        assert_eq!(path, "/");

        assert!(parse_http_url("https://foo.com/bar").is_none());
    }
}
