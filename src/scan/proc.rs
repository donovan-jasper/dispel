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
// Hash checking helper
// ---------------------------------------------------------------------------

/// Check a binary file against known hashes. Returns a Finding if matched.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", windows))]
fn check_known_hash(path: &str) -> Option<Finding> {
    use crate::signatures::hashes::{check_hash, sha256_file};

    let hash = sha256_file(path)?;
    let description = check_hash(&hash)?;
    Some(Finding::new(
        "proc",
        format!("Binary matches known imix hash: {}", description),
        Tier::Tier1,
        format!("path={} sha256={}", path, hash),
    ))
}

// ---------------------------------------------------------------------------
// Task 8: top-level proc scan entry point
// ---------------------------------------------------------------------------

/// Get the path of the current executable, used to skip self-scanning.
fn self_exe_path() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.to_string_lossy().to_string())
}

/// Case-insensitive path comparison for self-detection (needed on Windows
/// where path casing and prefix (\\?\, UNC) varies between APIs).
fn is_self_exe(path: &str, self_exe: &Option<String>) -> bool {
    match self_exe.as_deref() {
        Some(s) => {
            #[cfg(windows)]
            {
                // Normalize: strip \\?\ prefix, compare case-insensitive
                let norm_path = path.strip_prefix(r"\\?\").unwrap_or(path);
                let norm_self = s.strip_prefix(r"\\?\").unwrap_or(s);
                norm_path.eq_ignore_ascii_case(norm_self)
            }
            #[cfg(not(windows))]
            { path == s }
        }
        None => false,
    }
}

/// Scan process layer and return accumulated findings.
#[allow(unused_mut, unused_variables)]
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();
    let scanner = BinaryScanner::new();
    let self_exe = self_exe_path();
    // Tracks exe paths already binary-scanned (live process scan) so the
    // install-path section does not re-scan the same file.
    let mut scanned_paths: HashSet<String> = HashSet::new();

    // --- Linux-specific live process scanning ---
    #[cfg(target_os = "linux")]
    {
        use crate::platform::linux::enumerate_processes;

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

            // Binary scan of each live process executable (skip self).
            // When the exe has been deleted from disk, scan via /proc/<pid>/exe
            // (which remains readable) and rewrite the finding detail to show
            // the original path instead of the /proc path.
            if let Some(ref exe) = proc.exe_path {
                let is_self = is_self_exe(exe, &self_exe);
                if !is_self {
                    let scan_path = if proc.deleted_exe {
                        format!("/proc/{}/exe", proc.pid)
                    } else {
                        exe.clone()
                    };
                    let mut findings = scanner.scan_file(&scan_path);
                    if proc.deleted_exe {
                        let proc_path_prefix = format!("path={}", scan_path);
                        let real_path_detail = format!("path={} (deleted)", exe);
                        for f in &mut findings {
                            if f.detail == proc_path_prefix {
                                f.detail = real_path_detail.clone();
                            }
                        }
                    }
                    if verbose && !findings.is_empty() {
                        eprintln!(
                            "[proc] {} finding(s) in pid={} exe={}{}",
                            findings.len(),
                            proc.pid,
                            exe,
                            if proc.deleted_exe { " (deleted)" } else { "" }
                        );
                    }
                    for f in findings {
                        result.add_finding(f);
                    }
                    // Check against known hashes
                    if let Some(hash_finding) = check_known_hash(&scan_path) {
                        result.add_finding(hash_finding);
                    }
                    scanned_paths.insert(exe.clone());
                }
            }
        }
    }

    // --- Scan known dormant install paths (all platforms) ---
    #[cfg(target_os = "linux")]
    {
        for path in TIER1_INSTALL_PATHS_LINUX {
            let is_self = self_exe.as_deref().map_or(false, |s| {
                std::path::Path::new(path)
                    .canonicalize()
                    .map_or(false, |p| p.to_string_lossy() == s)
            });
            if is_self {
                continue;
            }
            if std::path::Path::new(path).exists() {
                // Report presence as Tier1 finding even before scanning bytes
                result.add_finding(Finding::new(
                    "proc",
                    "Realm C2 binary found at known install path",
                    Tier::Tier1,
                    format!("path={}", path),
                ));
                // Also do binary scan for additional evidence, but skip if the
                // path was already scanned as a live process exe.
                if !scanned_paths.contains(*path) {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
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

        // Windows processes that legitimately have high thread counts
        const HIGH_THREAD_ALLOWLIST: &[&str] = &[
            "system", "svchost.exe", "lsass.exe", "csrss.exe",
            "services.exe", "wmiprvse.exe", "searchindexer.exe",
            "microsoftedgeupdate.exe", "runtimebroker.exe",
        ];

        for proc_info in &procs {
            let lower_name = proc_info.name.to_lowercase();

            if proc_info.thread_count > 50
                && !HIGH_THREAD_ALLOWLIST.contains(&lower_name.as_str())
                && proc_info.pid != 4
            {
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
                let is_self = is_self_exe(path, &self_exe);
                if !is_self {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                    if let Some(hash_finding) = check_known_hash(path) {
                        result.add_finding(hash_finding);
                    }
                    scanned_paths.insert(path.clone());
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
                // Skip binary scan if already scanned as a live process exe.
                if !scanned_paths.contains(*path) {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                }
            }
        }
    }

    // --- BSD live process scanning ---
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        use crate::platform::bsd::enumerate_processes;
        use crate::signatures::strings;

        let procs = enumerate_processes();
        if verbose {
            eprintln!("[verbose] Found {} BSD processes", procs.len());
        }

        for proc_info in &procs {
            // Check process name against known imix binary names
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
                    format!(
                        "pid={} exe={}",
                        proc_info.pid,
                        proc_info.exe_path.as_deref().unwrap_or("<unknown>")
                    ),
                ));
            }

            // Binary scan of each live process executable (skip self)
            if let Some(ref exe) = proc_info.exe_path {
                let is_self = is_self_exe(exe, &self_exe);
                if !is_self {
                    let findings = scanner.scan_file(exe);
                    if verbose && !findings.is_empty() {
                        eprintln!(
                            "[proc] {} finding(s) in pid={} exe={}",
                            findings.len(),
                            proc_info.pid,
                            exe,
                        );
                    }
                    for f in findings {
                        result.add_finding(f);
                    }
                    // Check against known hashes
                    if let Some(hash_finding) = check_known_hash(exe) {
                        result.add_finding(hash_finding);
                    }
                    scanned_paths.insert(exe.clone());
                }
            }
        }

        // Check known BSD install paths
        let bsd_install_paths: &[&str] = &[
            "/bin/imix",
            "/usr/bin/imix",
            "/usr/local/bin/imix",
            "/tmp/imix",
            "/var/tmp/imix",
        ];
        for path in bsd_install_paths {
            let is_self = self_exe.as_deref().map_or(false, |s| {
                std::path::Path::new(path)
                    .canonicalize()
                    .map_or(false, |p| p.to_string_lossy() == s)
            });
            if is_self {
                continue;
            }
            if std::path::Path::new(path).exists() {
                result.add_finding(Finding::new(
                    "proc",
                    "Realm C2 binary found at known install path",
                    Tier::Tier1,
                    format!("path={}", path),
                ));
                if !scanned_paths.contains(*path) {
                    for f in scanner.scan_file(path) {
                        result.add_finding(f);
                    }
                }
            }
        }
    }

    let _ = verbose; // suppress unused warning on platforms with no live proc scan

    result
}
