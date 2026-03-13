use std::path::Path;

use crate::ScanResult;

/// Return true if the path refers to a known shell binary.
/// Comparison is done on the filename component only (not the full path),
/// so /usr/bin/bash and /bin/bash both match "bash".
pub fn is_shell_binary(path: &str) -> bool {
    const SHELL_NAMES: &[&str] = &[
        "bash",
        "sh",
        "zsh",
        "dash",
        "csh",
        "tcsh",
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "powershell",
    ];

    let filename = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    SHELL_NAMES.contains(&filename)
}

/// Check whether any fd in `fds` is a socket or points to ptmx while the
/// owning process is a shell binary.
///
/// `fds` is a slice of `(target, is_socket)` where `target` is the symlink
/// destination of the fd and `is_socket` indicates the kernel reported the
/// fd as a socket type.
///
/// Returns a Behavioral Finding if the process is a shell with a socket fd.
#[cfg(target_os = "linux")]
pub fn check_fd_redirected_to_socket(
    fds: &[(&str, bool)],
    proc_name: &str,
    pid: u32,
) -> Option<crate::Finding> {
    use crate::Tier;

    if !is_shell_binary(proc_name) {
        return None;
    }

    let has_socket = fds.iter().any(|(target, is_socket)| {
        *is_socket || target.starts_with("socket:") || target.contains("ptmx")
    });

    if has_socket {
        Some(crate::Finding::new(
            "behavior",
            "Possible reverse shell",
            Tier::Behavioral,
            format!("pid={} proc={}", pid, proc_name),
        ))
    } else {
        None
    }
}

/// Scan behavioral layer and return accumulated findings.
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();

    // --- Linux ---
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        use std::os::unix::fs::MetadataExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        use crate::{Finding, Tier};

        // 1. Enumerate processes and check shell processes for socket fd redirections.
        //    Read /proc directly so we don't depend on platform::linux which may be a stub.
        if let Ok(proc_entries) = fs::read_dir("/proc") {
            for entry in proc_entries.flatten() {
                let fname = entry.file_name();
                let fname_str = fname.to_string_lossy();

                // Only process numeric directories (PIDs)
                let pid: u32 = match fname_str.parse() {
                    Ok(n) => n,
                    Err(_) => continue,
                };

                // Read the process executable name via /proc/<pid>/comm
                let comm_path = format!("/proc/{}/comm", pid);
                let proc_name = match fs::read_to_string(&comm_path) {
                    Ok(s) => s.trim().to_string(),
                    Err(_) => continue,
                };

                if !is_shell_binary(&proc_name) {
                    continue;
                }

                // Enumerate file descriptors for this shell process
                let fd_dir = format!("/proc/{}/fd", pid);
                let fds: Vec<(String, bool)> = match fs::read_dir(&fd_dir) {
                    Ok(entries) => entries
                        .flatten()
                        .filter_map(|fd_entry| {
                            let link_target = fs::read_link(fd_entry.path()).ok()?;
                            let target_str = link_target.to_string_lossy().to_string();
                            let is_socket = target_str.starts_with("socket:");
                            Some((target_str, is_socket))
                        })
                        .collect(),
                    Err(_) => continue,
                };

                let fd_refs: Vec<(&str, bool)> =
                    fds.iter().map(|(s, b)| (s.as_str(), *b)).collect();

                if let Some(finding) = check_fd_redirected_to_socket(&fd_refs, &proc_name, pid) {
                    if verbose {
                        eprintln!(
                            "[behavior] possible reverse shell: pid={} proc={}",
                            pid, proc_name
                        );
                    }
                    result.add_finding(finding);
                }
            }
        }

        // 2. Check /etc/shadow atime — if accessed in the last 60 seconds,
        //    something read the shadow file recently (credential harvesting).
        {
            let shadow_path = "/etc/shadow";
            if let Ok(meta) = fs::metadata(shadow_path) {
                let atime_secs = meta.atime() as u64;
                let now_secs = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                if now_secs >= atime_secs && (now_secs - atime_secs) <= 60 {
                    if verbose {
                        eprintln!(
                            "[behavior] /etc/shadow accessed within the last 60 seconds"
                        );
                    }
                    result.add_finding(Finding::new(
                        "behavior",
                        "/etc/shadow accessed recently (possible credential harvesting)",
                        Tier::Behavioral,
                        format!(
                            "path={} atime_delta_secs={}",
                            shadow_path,
                            now_secs - atime_secs
                        ),
                    ));
                }
            }
        }
    }

    // --- Windows stub ---
    #[cfg(windows)]
    {
        // TODO: check WMI for suspicious shell processes
    }

    // --- BSD stub ---
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        // TODO: enumerate BSD processes for shell fd redirections
    }

    let _ = verbose; // suppress unused warning when no platform matches

    result
}
