use regex::Regex;
use std::fs;

use crate::{Finding, ScanResult, Tier};

/// Check whether a string matches UUID v4 format.
/// UUID v4: xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx
pub fn is_uuid_v4(s: &str) -> bool {
    let re = Regex::new(
        r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    .expect("UUID v4 regex is valid");
    re.is_match(s)
}

/// Read the file at `path`, trim whitespace, and check:
///   - Length is exactly 36 bytes (after trim)
///   - Content matches UUID v4 format
///
/// Returns a Tier2 Finding if both conditions hold.
pub fn check_uuid_file(path: &str) -> Option<Finding> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();

    if trimmed.len() != 36 {
        return None;
    }

    if is_uuid_v4(trimmed) {
        Some(Finding::new(
            "persist",
            "Realm C2 beacon ID file found",
            Tier::Tier2,
            format!("path={} uuid={}", path, trimmed),
        ))
    } else {
        None
    }
}

/// Scan persistence layer and return accumulated findings.
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();

    // --- Linux ---
    #[cfg(target_os = "linux")]
    {
        use std::time::SystemTime;

        use crate::signatures::strings::{
            BEACON_ID_PATHS_LINUX, SYSTEMD_PATHS, SYSVINIT_PATH, TIER1_SERVICE_NAMES,
        };

        // 1. Check beacon ID paths
        for path in BEACON_ID_PATHS_LINUX {
            if let Some(finding) = check_uuid_file(path) {
                if verbose {
                    eprintln!("[persist] beacon ID found at {}", path);
                }
                result.add_finding(finding);
            }
        }

        // 2. Check systemd unit files for TIER1_SERVICE_NAMES
        for unit_path in SYSTEMD_PATHS {
            if let Ok(content) = fs::read_to_string(unit_path) {
                for svc_name in TIER1_SERVICE_NAMES {
                    if content.contains(svc_name) {
                        if verbose {
                            eprintln!(
                                "[persist] service name '{}' found in {}",
                                svc_name, unit_path
                            );
                        }
                        result.add_finding(Finding::new(
                            "persist",
                            "Realm C2 service name found in systemd unit",
                            Tier::Tier1,
                            format!("path={} name={}", unit_path, svc_name),
                        ));
                        // Only report the first match per file to avoid duplicates
                        break;
                    }
                }
            }
        }

        // 3. Check sysvinit script
        if let Ok(content) = fs::read_to_string(SYSVINIT_PATH) {
            for svc_name in TIER1_SERVICE_NAMES {
                if content.contains(svc_name) {
                    if verbose {
                        eprintln!(
                            "[persist] service name '{}' found in {}",
                            svc_name, SYSVINIT_PATH
                        );
                    }
                    result.add_finding(Finding::new(
                        "persist",
                        "Realm C2 service name found in sysvinit script",
                        Tier::Tier1,
                        format!("path={} name={}", SYSVINIT_PATH, svc_name),
                    ));
                    break;
                }
            }
        }

        // 4. Check for timestomped binaries: flag files with a future mtime
        //    relative to /bin/sh and also in the future relative to now.
        let reference_mtime = fs::metadata("/bin/sh")
            .and_then(|m| m.modified())
            .ok();

        if let Some(ref_mtime) = reference_mtime {
            let scan_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"];
            for dir in &scan_dirs {
                let entries = match fs::read_dir(dir) {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    let meta = match entry_path.metadata() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if !meta.is_file() {
                        continue;
                    }
                    let mtime = match meta.modified() {
                        Ok(t) => t,
                        Err(_) => continue,
                    };

                    // Flag anything that is MORE than 365 days newer than /bin/sh
                    // AND also in the future (timestamp manipulation).
                    let delta = if mtime > ref_mtime {
                        mtime.duration_since(ref_mtime).unwrap_or_default()
                    } else {
                        continue;
                    };

                    if delta.as_secs() > 365 * 24 * 3600 {
                        let now = SystemTime::now();
                        if mtime > now {
                            if verbose {
                                eprintln!(
                                    "[persist] future mtime on {}",
                                    entry_path.display()
                                );
                            }
                            result.add_finding(Finding::new(
                                "persist",
                                "Binary has future modification time (possible timestomping)",
                                Tier::Behavioral,
                                format!("path={}", entry_path.display()),
                            ));
                        }
                    }
                }
            }
        }
    }

    // --- BSD ---
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        use crate::signatures::strings::BEACON_ID_PATHS_BSD;

        for path in BEACON_ID_PATHS_BSD {
            if let Some(finding) = check_uuid_file(path) {
                if verbose {
                    eprintln!("[persist] beacon ID found at {}", path);
                }
                result.add_finding(finding);
            }
        }
    }

    // --- Windows ---
    #[cfg(windows)]
    {
        use crate::platform::windows;
        use crate::signatures::strings::BEACON_ID_PATHS_WINDOWS;

        // Check beacon ID paths
        for path in BEACON_ID_PATHS_WINDOWS {
            if let Some(finding) = check_uuid_file(path) {
                if verbose {
                    eprintln!("[persist] beacon ID found at {}", path);
                }
                result.add_finding(finding);
            }
        }

        // Registry check
        for finding in windows::check_registry_imix() {
            result.add_finding(finding);
        }

        // Service check
        for finding in windows::check_windows_services() {
            result.add_finding(finding);
        }

        // Timestomp check on system directories
        let system_paths = [
            r"C:\Windows\System32",
            r"C:\Windows\SysWOW64",
            r"C:\Windows\Temp",
        ];
        for dir in &system_paths {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if windows::check_timestomp(path.to_str().unwrap_or("")) {
                            result.add_finding(Finding::new(
                                "persist",
                                format!(
                                    "Binary timestomped to match cmd.exe: {}",
                                    path.display()
                                ),
                                Tier::Tier2,
                                path.display().to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    let _ = verbose; // suppress unused warning when no platform block matches

    result
}
