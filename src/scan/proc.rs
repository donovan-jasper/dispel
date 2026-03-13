use aho_corasick::AhoCorasick;
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::File;

use crate::signatures::strings::{
    all_signatures, GRPC_PATHS, ELDRITCH_DISTINCTIVE, ELDRITCH_AGENT_API,
    ELDRITCH_OFFENSIVE, ELDRITCH_REPORT, TIER2_STRINGS,
};
#[cfg(target_os = "linux")]
use crate::signatures::strings::TIER1_INSTALL_PATHS_LINUX;
use crate::{Finding, ScanResult, Tier};

const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024; // 200 MB

/// Category label for a matched pattern, used in Finding descriptions.
fn categorize_pattern(pattern: &str) -> &'static str {
    if GRPC_PATHS.contains(&pattern) {
        return "gRPC service path";
    }
    if ELDRITCH_DISTINCTIVE.contains(&pattern) {
        return "Eldritch distinctive function";
    }
    if ELDRITCH_AGENT_API.contains(&pattern) {
        return "Eldritch agent API";
    }
    if ELDRITCH_OFFENSIVE.contains(&pattern) {
        return "Eldritch offensive capability";
    }
    if ELDRITCH_REPORT.contains(&pattern) {
        return "Eldritch report module";
    }
    if TIER2_STRINGS.contains(&pattern) {
        return "Realm C2 string indicator";
    }
    "binary signature"
}

/// Aho-Corasick binary scanner backed by all_signatures().
pub struct BinaryScanner {
    ac: AhoCorasick,
    /// Parallel vec of (pattern_str, tier) matching ac pattern indices.
    patterns: Vec<(String, Tier)>,
}

impl BinaryScanner {
    /// Build the automaton from all signatures.
    pub fn new() -> Self {
        let sigs = all_signatures();
        let patterns: Vec<(String, Tier)> = sigs
            .iter()
            .map(|(s, t)| (s.to_string(), t.clone()))
            .collect();
        let pattern_strs: Vec<&str> = patterns.iter().map(|(s, _)| s.as_str()).collect();
        let ac = AhoCorasick::new(pattern_strs).expect("failed to build Aho-Corasick automaton");
        Self { ac, patterns }
    }

    /// Scan raw bytes for all signature matches.
    /// Deduplicates by pattern string so a repeated pattern produces one Finding.
    pub fn scan_bytes(&self, data: &[u8], binary_path: &str) -> Vec<Finding> {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut findings: Vec<Finding> = Vec::new();

        for mat in self.ac.find_iter(data) {
            let idx = mat.pattern().as_usize();
            if seen.insert(idx) {
                let (pattern, tier) = &self.patterns[idx];
                let category = categorize_pattern(pattern.as_str());
                let description = format!("{}: {}", category, pattern);
                findings.push(Finding::new(
                    "proc",
                    description,
                    tier.clone(),
                    format!("path={}", binary_path),
                ));
            }
        }

        findings
    }

    /// Memory-map a file and scan it.
    /// Skips files that are empty or larger than MAX_FILE_SIZE.
    pub fn scan_file(&self, path: &str) -> Vec<Finding> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let metadata = match file.metadata() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        let size = metadata.len();
        if size == 0 || size > MAX_FILE_SIZE {
            return Vec::new();
        }

        // Safety: the file is read-only and we do not mutate the mapping.
        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };

        self.scan_bytes(&mmap, path)
    }
}

impl Default for BinaryScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Task 8: top-level proc scan entry point
// ---------------------------------------------------------------------------

/// Scan process layer and return accumulated findings.
#[allow(unused_mut, unused_variables)]
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();
    let scanner = BinaryScanner::new();

    // --- Linux-specific live process scanning ---
    #[cfg(target_os = "linux")]
    {
        use crate::platform::linux::{enumerate_processes, ProcessInfo};

        let procs = enumerate_processes();

        for proc in &procs {
            // Behavioral: deleted executable on disk (common after dropper cleanup)
            if proc.deleted_exe {
                result.add_finding(Finding::new(
                    "proc",
                    "Running process has deleted executable on disk",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} exe={}",
                        proc.pid,
                        proc.name,
                        proc.exe_path.as_deref().unwrap_or("<unknown>")
                    ),
                ));
            }

            // Behavioral: suspiciously high thread count (>50)
            if proc.thread_count > 50 {
                result.add_finding(Finding::new(
                    "proc",
                    "Process has unusually high thread count",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} threads={}",
                        proc.pid, proc.name, proc.thread_count
                    ),
                ));
            }

            // Binary scan of each live process executable
            if let Some(ref exe) = proc.exe_path {
                if !proc.deleted_exe {
                    let findings = scanner.scan_file(exe);
                    if verbose && !findings.is_empty() {
                        eprintln!(
                            "[proc] {} finding(s) in pid={} exe={}",
                            findings.len(),
                            proc.pid,
                            exe
                        );
                    }
                    for f in findings {
                        result.add_finding(f);
                    }
                }
            }
        }
    }

    // --- Scan known dormant install paths (all platforms) ---
    #[cfg(target_os = "linux")]
    {
        for path in TIER1_INSTALL_PATHS_LINUX {
            if std::path::Path::new(path).exists() {
                // Report presence as Tier1 finding even before scanning bytes
                result.add_finding(Finding::new(
                    "proc",
                    "Realm C2 binary found at known install path",
                    Tier::Tier1,
                    format!("path={}", path),
                ));
                // Also do binary scan for additional evidence
                for f in scanner.scan_file(path) {
                    result.add_finding(f);
                }
            }
        }
    }

    // --- Windows ---
    #[cfg(windows)]
    {
        use crate::platform::windows;
        use crate::signatures::strings;

        let procs = windows::enumerate_processes();
        if verbose {
            eprintln!("[verbose] Found {} Windows processes", procs.len());
        }

        for proc_info in &procs {
            if proc_info.thread_count > 50 {
                result.add_finding(Finding::new(
                    "proc",
                    format!(
                        "Process {} (PID {}) has {} threads",
                        proc_info.name, proc_info.pid, proc_info.thread_count
                    ),
                    Tier::Behavioral,
                    proc_info.exe_path.clone().unwrap_or_default(),
                ));
            }

            let lower_name = proc_info.name.to_lowercase();
            if strings::TIER1_BINARY_NAMES
                .iter()
                .any(|n| lower_name == *n)
            {
                result.add_finding(Finding::new(
                    "proc",
                    format!(
                        "Process named '{}' matches known imix name",
                        proc_info.name
                    ),
                    Tier::Tier1,
                    proc_info.exe_path.clone().unwrap_or_default(),
                ));
            }

            if let Some(ref path) = proc_info.exe_path {
                for f in scanner.scan_file(path) {
                    result.add_finding(f);
                }
            }
        }

        for path in strings::TIER1_INSTALL_PATHS_WINDOWS {
            if std::path::Path::new(path).exists() {
                result.add_finding(Finding::new(
                    "proc",
                    format!("Known imix install path exists: {}", path),
                    Tier::Tier1,
                    path.to_string(),
                ));
                for f in scanner.scan_file(path) {
                    result.add_finding(f);
                }
            }
        }
    }

    // --- BSD stub ---
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        let _ = verbose;
        // TODO: enumerate BSD processes via sysctl kinfo_proc
    }

    let _ = verbose; // suppress unused warning on platforms with no live proc scan

    result
}
