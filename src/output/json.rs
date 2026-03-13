use crate::{Finding, ScanResult};

/// Print a full scan result as pretty-printed JSON to stdout.
pub fn print_result(result: &ScanResult) {
    match serde_json::to_string_pretty(result) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}

/// Print a single finding as a compact JSON line (for watch mode streaming output).
pub fn print_finding_line(finding: &Finding) {
    match serde_json::to_string(finding) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}
