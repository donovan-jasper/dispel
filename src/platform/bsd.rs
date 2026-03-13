// BSD platform backend — process enumeration via `ps` for FreeBSD/OpenBSD/NetBSD.

use std::process::Command;

use super::ProcessInfo;

/// Enumerate all processes on BSD by parsing `ps -axo pid,comm,args`.
/// Falls back gracefully if ps is unavailable.
pub fn enumerate_processes() -> Vec<ProcessInfo> {
    let output = match Command::new("ps")
        .args(["-axo", "pid,comm,args"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    if !output.status.success() {
        return Vec::new();
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut result = Vec::new();

    for line in stdout.lines().skip(1) {
        // skip header
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Format: "  PID COMM ARGS..."
        let mut parts = trimmed.splitn(3, char::is_whitespace);

        let pid_str = match parts.next() {
            Some(s) => s.trim(),
            None => continue,
        };
        let pid: u32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Skip whitespace between fields
        let comm = match parts.next() {
            Some(s) => s.trim().to_string(),
            None => continue,
        };

        // The rest is the full command line (args)
        let args = parts.next().map(|s| s.trim().to_string()).unwrap_or_default();

        // Extract exe_path: first token of args, or try procstat on FreeBSD
        let exe_path = extract_exe_path(pid, &args);

        result.push(ProcessInfo {
            pid,
            name: comm,
            exe_path,
            deleted_exe: false,  // BSD doesn't track deleted exe the same way
            thread_count: 1,     // not easily available via ps
        });
    }

    result
}

/// Try to determine the executable path for a process.
/// First attempts `procstat -b <pid>` (FreeBSD), then falls back to
/// parsing the first token of the args column.
fn extract_exe_path(pid: u32, args: &str) -> Option<String> {
    // Try procstat on FreeBSD
    #[cfg(target_os = "freebsd")]
    {
        if let Some(path) = procstat_exe_path(pid) {
            return Some(path);
        }
    }

    // Fallback: first token of args if it looks like an absolute path
    let first_token = args.split_whitespace().next().unwrap_or("");
    if first_token.starts_with('/') {
        Some(first_token.to_string())
    } else {
        None
    }
}

/// Use `procstat -b <pid>` on FreeBSD to get the binary path.
#[cfg(target_os = "freebsd")]
fn procstat_exe_path(pid: u32) -> Option<String> {
    let output = Command::new("procstat")
        .args(["-b", &pid.to_string()])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output format: "  PID COMM            PATH"
    // Skip header, parse last field
    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // The path is the last whitespace-delimited field
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() >= 3 {
            let path = fields[fields.len() - 1];
            if path.starts_with('/') {
                return Some(path.to_string());
            }
        }
    }

    None
}
