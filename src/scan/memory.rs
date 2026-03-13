use crate::{Finding, ScanResult, Tier};

/// Scan for in-memory indicators of Realm C2 implants.
/// This goes beyond filesystem-based binary scanning to detect:
/// - Signatures in live process memory (catches deleted/packed binaries)
/// - Anonymous executable memory regions (fileless execution)
/// - Process masquerading (exe vs cmdline mismatch)
/// - memfd-based execution
/// - Suspicious shared library load paths
/// - IMIX-related environment variables
pub fn scan(verbose: bool) -> ScanResult {
    let mut result = ScanResult::new();
    let self_pid = std::process::id();

    #[cfg(target_os = "linux")]
    {
        scan_linux(&mut result, self_pid, verbose);
    }

    #[cfg(windows)]
    {
        scan_windows(&mut result, self_pid, verbose);
    }

    let _ = (verbose, self_pid);
    result
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn scan_linux(result: &mut ScanResult, self_pid: u32, verbose: bool) {
    use crate::scan::proc::BinaryScanner;
    use std::fs;

    let scanner = BinaryScanner::new();

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir.flatten() {
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        let pid: u32 = match fname_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // Skip self
        if pid == self_pid {
            continue;
        }

        let pid_path = format!("/proc/{}", pid);

        // Get process name for reporting
        let proc_name = fs::read_to_string(format!("{}/comm", pid_path))
            .unwrap_or_default()
            .trim()
            .to_string();
        if proc_name.is_empty() {
            continue;
        }

        // 1. Process masquerading detection
        check_masquerading(result, pid, &pid_path, &proc_name, verbose);

        // 2. Environment variable inspection
        check_environ(result, pid, &pid_path, &proc_name, verbose);

        // 3. Memory maps analysis (anonymous exec, memfd, suspicious .so paths)
        let maps = check_maps(result, pid, &pid_path, &proc_name, verbose);

        // 4. memfd file descriptor detection
        check_memfd_fds(result, pid, &pid_path, &proc_name, verbose);

        // 5. Process memory scanning for signatures
        // Skip common service processes whose heap may contain our own scan output
        // (e.g., sshd contains our output text when we run through SSH)
        if let Some(ref regions) = maps {
            let skip_mem_scan = matches!(
                proc_name.as_str(),
                "sshd" | "login" | "su" | "sudo" | "screen" | "tmux" | "script"
            );
            if !skip_mem_scan {
                scan_process_memory(result, &scanner, pid, &pid_path, &proc_name, regions, verbose);
            }
        }
    }
}

/// Memory region parsed from /proc/<pid>/maps.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct MemRegion {
    start: u64,
    end: u64,
    perms: String,
    pathname: String,
}

#[cfg(target_os = "linux")]
impl MemRegion {
    fn is_readable(&self) -> bool {
        self.perms.starts_with('r')
    }

    fn is_executable(&self) -> bool {
        self.perms.len() >= 3 && self.perms.as_bytes()[2] == b'x'
    }

    fn is_writable(&self) -> bool {
        self.perms.len() >= 2 && self.perms.as_bytes()[1] == b'w'
    }

    fn is_anonymous(&self) -> bool {
        self.pathname.is_empty()
    }

    fn is_memfd(&self) -> bool {
        self.pathname.starts_with("/memfd:")
            || self.pathname.starts_with("memfd:")
    }

    fn is_file_backed(&self) -> bool {
        self.pathname.starts_with('/')
            && !self.is_memfd()
    }
}

/// Parse /proc/<pid>/maps into memory regions.
#[cfg(target_os = "linux")]
fn parse_maps(pid_path: &str) -> Option<Vec<MemRegion>> {
    use std::fs;

    let content = fs::read_to_string(format!("{}/maps", pid_path)).ok()?;
    let mut regions = Vec::new();

    for line in content.lines() {
        // Format: addr-addr perms offset dev inode pathname
        let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
        if parts.len() < 2 {
            continue;
        }

        let addr_range = parts[0];
        let perms = parts[1].to_string();

        let pathname = if parts.len() >= 6 {
            parts[5].trim().to_string()
        } else {
            String::new()
        };

        let (start, end) = match addr_range.split_once('-') {
            Some((s, e)) => {
                let start = u64::from_str_radix(s, 16).unwrap_or(0);
                let end = u64::from_str_radix(e, 16).unwrap_or(0);
                (start, end)
            }
            None => continue,
        };

        regions.push(MemRegion {
            start,
            end,
            perms,
            pathname,
        });
    }

    Some(regions)
}

/// Check for process masquerading: exe symlink doesn't match cmdline argv[0].
#[cfg(target_os = "linux")]
fn check_masquerading(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) {
    use std::fs;
    use std::path::Path;

    let exe_target = match fs::read_link(format!("{}/exe", pid_path)) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return,
    };

    // Strip " (deleted)" suffix
    let exe_clean = exe_target
        .strip_suffix(" (deleted)")
        .unwrap_or(&exe_target);

    let cmdline = match fs::read(format!("{}/cmdline", pid_path)) {
        Ok(data) => data,
        Err(_) => return,
    };

    if cmdline.is_empty() {
        return;
    }

    // argv[0] is the first null-terminated string
    let argv0_end = cmdline.iter().position(|&b| b == 0).unwrap_or(cmdline.len());
    let argv0 = String::from_utf8_lossy(&cmdline[..argv0_end]).trim().to_string();

    if argv0.is_empty() {
        return;
    }

    // Compare the basename of exe vs argv0
    let exe_basename = Path::new(exe_clean)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let argv0_basename = Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // If argv0 looks like a path (contains /), compare basenames
    // If argv0 is just a name, compare against exe basename
    if !exe_basename.is_empty() && !argv0_basename.is_empty() && exe_basename != argv0_basename {
        // Skip kernel threads and common legitimate renames
        if argv0_basename.starts_with('[') || exe_basename.starts_with('[')
            || argv0_basename.starts_with('(') || exe_basename.starts_with('(')
        {
            return;
        }
        // Some interpreters legitimately differ (python3 -> python3.11)
        if exe_basename.starts_with(argv0_basename) || argv0_basename.starts_with(exe_basename) {
            return;
        }
        // Common legitimate masquerading patterns
        // systemd/init: PID 1 often runs as /sbin/init -> /usr/lib/systemd/systemd
        // busybox: multicall binary that appears as sh, ls, etc.
        // udevadm: launched as systemd-udevd
        // sd-pam: systemd PAM helper
        const LEGIT_PAIRS: &[(&str, &str)] = &[
            ("systemd", "init"),
            ("udevadm", "systemd-udevd"),
            ("busybox", "sh"),
            ("busybox", "ls"),
            ("busybox", "cat"),
            ("busybox", "grep"),
            ("busybox", "awk"),
            ("busybox", "sed"),
            ("busybox", "vi"),
            ("busybox", "wget"),
            ("busybox", "tar"),
            ("busybox", "gzip"),
            ("busybox", "find"),
            ("busybox", "xargs"),
            ("busybox", "entry"),
            ("systemd", "sd-pam"),
            ("containerd", "k3s"),
            ("k3s", "containerd"),
            ("dash", "sh"),
            ("k3s", "containerd-shim"),
        ];
        for (exe_match, argv0_match) in LEGIT_PAIRS {
            if exe_basename == *exe_match && argv0_basename == *argv0_match {
                return;
            }
            if exe_basename.contains(exe_match) && argv0_basename == *argv0_match {
                return;
            }
        }

        if verbose {
            eprintln!(
                "[memory] masquerading: pid={} exe={} argv0={}",
                pid, exe_clean, argv0
            );
        }
        result.add_finding(Finding::new(
            "memory",
            "Process masquerading: exe does not match argv[0]",
            Tier::Behavioral,
            format!(
                "pid={} name={} exe={} argv0={}",
                pid, proc_name, exe_clean, argv0
            ),
        ));
    }
}

/// Check /proc/<pid>/environ for IMIX-related environment variables.
#[cfg(target_os = "linux")]
fn check_environ(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) {
    use std::fs;

    let environ = match fs::read(format!("{}/environ", pid_path)) {
        Ok(data) => data,
        Err(_) => return,
    };

    // Environment is null-byte separated KEY=VALUE pairs
    let suspicious_prefixes: &[&str] = &[
        "IMIX_",
        "IMIX_CALLBACK",
        "IMIX_BEACON",
        "IMIX_SERVER",
        "IMIX_HOST",
        "IMIX_TRANSPORT",
        "IMIX_LOG",
        "IMIX_CONFIG",
        "C2_CALLBACK",
        "C2_SERVER",
        "BEACON_",
        "CALLBACK_URI",
        "CALLBACK_INTERVAL",
    ];

    for var_bytes in environ.split(|&b| b == 0) {
        if var_bytes.is_empty() {
            continue;
        }
        let var = String::from_utf8_lossy(var_bytes);
        for prefix in suspicious_prefixes {
            if var.starts_with(prefix) {
                if verbose {
                    eprintln!(
                        "[memory] suspicious env var: pid={} var={}",
                        pid,
                        &var[..var.len().min(80)]
                    );
                }
                result.add_finding(Finding::new(
                    "memory",
                    format!("Suspicious environment variable: {}", prefix),
                    Tier::Tier2,
                    format!(
                        "pid={} name={} var={}",
                        pid,
                        proc_name,
                        &var[..var.len().min(120)]
                    ),
                ));
                break;
            }
        }
    }
}

/// Analyze /proc/<pid>/maps for:
/// - Anonymous executable regions (rwxp with no file)
/// - memfd-backed executable regions
/// - Shared libraries loaded from suspicious paths
/// Returns parsed regions for later use in memory scanning.
#[cfg(target_os = "linux")]
fn check_maps(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) -> Option<Vec<MemRegion>> {
    let regions = parse_maps(pid_path)?;

    let suspicious_lib_dirs: &[&str] = &[
        "/tmp/",
        "/dev/shm/",
        "/var/tmp/",
        "/run/shm/",
    ];

    let mut found_anon_rwx = false;
    let mut found_memfd = false;

    for region in &regions {
        // Anonymous executable regions (no backing file, executable)
        if region.is_anonymous() && region.is_executable() {
            let size = region.end - region.start;
            // Skip tiny regions (<4KB) -- likely trampolines or signal handlers
            if size < 4096 {
                continue;
            }

            if region.is_writable() && !found_anon_rwx {
                // RWX anonymous -- very suspicious
                found_anon_rwx = true;
                if verbose {
                    eprintln!(
                        "[memory] anon RWX region: pid={} addr={:#x}-{:#x} size={}",
                        pid, region.start, region.end, size
                    );
                }
                result.add_finding(Finding::new(
                    "memory",
                    "Anonymous RWX memory region (possible code injection)",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} addr={:#x}-{:#x} size={} perms={}",
                        pid, proc_name, region.start, region.end, size, region.perms
                    ),
                ));
            }
            // We don't flag r-xp anonymous as aggressively -- JIT and some runtimes use these
        }

        // memfd-backed executable regions
        if region.is_memfd() && region.is_executable() && !found_memfd {
            found_memfd = true;
            if verbose {
                eprintln!(
                    "[memory] memfd exec: pid={} path={}",
                    pid, region.pathname
                );
            }
            result.add_finding(Finding::new(
                "memory",
                "Executable code loaded from memfd (fileless execution)",
                Tier::Tier2,
                format!(
                    "pid={} name={} memfd={} perms={}",
                    pid, proc_name, region.pathname, region.perms
                ),
            ));
        }

        // Shared libraries from suspicious paths
        if region.is_file_backed() && region.is_executable() {
            let path_lower = region.pathname.to_lowercase();
            // Check for .so files loaded from suspicious directories
            if path_lower.contains(".so") || path_lower.ends_with(".so") {
                for suspect_dir in suspicious_lib_dirs {
                    if region.pathname.starts_with(suspect_dir) {
                        if verbose {
                            eprintln!(
                                "[memory] suspicious .so: pid={} path={}",
                                pid, region.pathname
                            );
                        }
                        result.add_finding(Finding::new(
                            "memory",
                            "Shared library loaded from suspicious path",
                            Tier::Behavioral,
                            format!(
                                "pid={} name={} lib={}",
                                pid, proc_name, region.pathname
                            ),
                        ));
                        break;
                    }
                }
            }

            // Check for hidden directory paths (contain /.)
            if region.pathname.contains("/.") && !region.pathname.contains("/.cache") {
                result.add_finding(Finding::new(
                    "memory",
                    "Shared library loaded from hidden directory",
                    Tier::Behavioral,
                    format!(
                        "pid={} name={} lib={}",
                        pid, proc_name, region.pathname
                    ),
                ));
            }
        }
    }

    Some(regions)
}

/// Check /proc/<pid>/fd/ for memfd file descriptors.
#[cfg(target_os = "linux")]
fn check_memfd_fds(
    result: &mut ScanResult,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    verbose: bool,
) {
    use std::fs;

    let fd_dir = format!("{}/fd", pid_path);
    let entries = match fs::read_dir(&fd_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let target = match fs::read_link(entry.path()) {
            Ok(t) => t.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if target.starts_with("/memfd:") || target.starts_with("memfd:") {
            if verbose {
                eprintln!(
                    "[memory] memfd fd: pid={} fd={} target={}",
                    pid,
                    entry.file_name().to_string_lossy(),
                    target
                );
            }
            result.add_finding(Finding::new(
                "memory",
                "Process has memfd file descriptor (fileless staging)",
                Tier::Behavioral,
                format!(
                    "pid={} name={} fd={} target={}",
                    pid,
                    proc_name,
                    entry.file_name().to_string_lossy(),
                    target
                ),
            ));
            // Only report once per process
            return;
        }
    }
}

/// Scan process memory by reading /proc/<pid>/mem using the maps as a guide.
/// Only scans readable, non-file-backed regions (heap, stack, anonymous)
/// plus the main executable region. Uses the Aho-Corasick scanner.
#[cfg(target_os = "linux")]
fn scan_process_memory(
    result: &mut ScanResult,
    scanner: &crate::scan::proc::BinaryScanner,
    pid: u32,
    pid_path: &str,
    proc_name: &str,
    regions: &[MemRegion],
    verbose: bool,
) {
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::Read;
    use std::os::unix::io::AsRawFd;

    let mem_path = format!("{}/mem", pid_path);
    let mem_file = match File::open(&mem_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let mut found_patterns: HashSet<String> = HashSet::new();
    let mut pending_findings: Vec<Finding> = Vec::new();
    let mut total_scanned: u64 = 0;
    const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024; // 100 MB cap per process
    const MAX_REGION_SIZE: u64 = 32 * 1024 * 1024; // 32 MB cap per region

    for region in regions {
        if !region.is_readable() {
            continue;
        }

        let size = region.end - region.start;
        if size == 0 || size > MAX_REGION_SIZE {
            continue;
        }

        if total_scanned + size > MAX_SCAN_BYTES {
            break;
        }

        // Skip vDSO, vsyscall, vvar
        if region.pathname.starts_with("[vdso]")
            || region.pathname.starts_with("[vsyscall]")
            || region.pathname.starts_with("[vvar]")
        {
            continue;
        }

        // For file-backed regions, only scan if they're from suspicious paths or the main exe
        if region.is_file_backed() {
            let dominated_by_system = region.pathname.starts_with("/usr/lib")
                || region.pathname.starts_with("/lib")
                || region.pathname.starts_with("/usr/share")
                || region.pathname.starts_with("/usr/libexec");
            if dominated_by_system {
                continue;
            }
        }

        // Read the region via pread
        let mut buf = vec![0u8; size as usize];
        let bytes_read = unsafe {
            libc::pread(
                mem_file.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size as usize,
                region.start as i64,
            )
        };

        if bytes_read <= 0 {
            continue;
        }

        let buf = &buf[..bytes_read as usize];
        total_scanned += bytes_read as u64;

        // Run Aho-Corasick on the memory chunk
        let findings = scanner.scan_bytes(buf, &format!("pid:{}", pid));

        for f in findings {
            // Deduplicate across regions within this process
            if found_patterns.insert(f.description.clone()) {
                if verbose {
                    eprintln!(
                        "[memory] signature in memory: pid={} name={} {}",
                        pid, proc_name, f.description
                    );
                }
                // Collect finding (will only be reported if threshold met)
                pending_findings.push(Finding::new(
                    "memory",
                    format!("In-memory: {}", f.description),
                    f.tier,
                    format!(
                        "pid={} name={} region={:#x}-{:#x} backing={}",
                        pid,
                        proc_name,
                        region.start,
                        region.end,
                        if region.pathname.is_empty() {
                            "[anonymous]"
                        } else {
                            &region.pathname
                        }
                    ),
                ));
            }
        }
    }

    if verbose && total_scanned > 0 && !pending_findings.is_empty() {
        eprintln!(
            "[memory] pid={} scanned {} bytes, {} unique matches",
            pid,
            total_scanned,
            pending_findings.len()
        );
    }

    // Only report findings if a process has 3+ unique matches.
    // A single match (e.g., "ssh_exec" in sshd) is likely noise.
    // Multiple distinct Realm signatures in one process is a strong signal.
    if pending_findings.len() >= 3 {
        for f in pending_findings {
            result.add_finding(f);
        }
    } else if verbose && !pending_findings.is_empty() {
        eprintln!(
            "[memory] pid={} name={}: {} match(es) below threshold, suppressed",
            pid, proc_name, pending_findings.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn scan_windows(result: &mut ScanResult, self_pid: u32, verbose: bool) {
    use crate::platform::windows::enumerate_processes;
    use crate::scan::proc::BinaryScanner;

    let scanner = BinaryScanner::new();
    let procs = enumerate_processes();

    for proc_info in &procs {
        if proc_info.pid == self_pid || proc_info.pid == 0 || proc_info.pid == 4 {
            continue;
        }

        // 1. Private executable memory detection + memory scanning
        scan_windows_process_memory(
            result,
            &scanner,
            proc_info.pid,
            &proc_info.name,
            verbose,
        );
    }
}

/// Scan a Windows process for:
/// - Private executable memory regions (MEM_PRIVATE + PAGE_EXECUTE*)
/// - Realm C2 signatures in process memory
/// - Thread start addresses in private memory
#[cfg(windows)]
fn scan_windows_process_memory(
    result: &mut ScanResult,
    scanner: &crate::scan::proc::BinaryScanner,
    pid: u32,
    proc_name: &str,
    verbose: bool,
) {
    use std::collections::HashSet;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_PRIVATE,
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return;
        }

        let mut address: usize = 0;
        let mut found_private_exec = false;
        let mut found_patterns: HashSet<String> = HashSet::new();
        let mut pending_findings: Vec<Finding> = Vec::new();
        let mut total_scanned: u64 = 0;
        const MAX_SCAN_BYTES: u64 = 100 * 1024 * 1024;
        const MAX_REGION_SIZE: usize = 32 * 1024 * 1024;

        loop {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let ret = VirtualQueryEx(
                handle,
                address as *const _,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );

            if ret == 0 {
                break;
            }

            let is_exec = matches!(
                mbi.Protect,
                PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            );

            // Check for private executable regions
            // Skip small regions (<=8KB) as many legitimate Windows processes
            // use small private exec regions for JIT, .NET, trampolines, etc.
            if mbi.Type == MEM_PRIVATE && is_exec && mbi.RegionSize > 8192 && !found_private_exec {
                found_private_exec = true;
                if verbose {
                    eprintln!(
                        "[memory] private exec region: pid={} addr={:#x} size={} protect={:#x}",
                        pid, mbi.BaseAddress as usize, mbi.RegionSize, mbi.Protect
                    );
                }

                let tier = if mbi.Protect == PAGE_EXECUTE_READWRITE {
                    Tier::Tier2 // RWX is very suspicious
                } else {
                    Tier::Behavioral
                };

                pending_findings.push(Finding::new(
                    "memory",
                    "Private executable memory region (possible code injection)",
                    tier,
                    format!(
                        "pid={} name={} addr={:#x} size={} protect={:#x}",
                        pid,
                        proc_name,
                        mbi.BaseAddress as usize,
                        mbi.RegionSize,
                        mbi.Protect
                    ),
                ));
            }

            // Scan readable non-system regions for signatures
            if is_exec && mbi.RegionSize >= 4096 && mbi.RegionSize <= MAX_REGION_SIZE {
                // Skip MEM_IMAGE regions backed by system DLLs (too noisy)
                let should_scan = mbi.Type == MEM_PRIVATE || mbi.Type != MEM_IMAGE;

                if should_scan && total_scanned + mbi.RegionSize as u64 <= MAX_SCAN_BYTES {
                    let mut buf = vec![0u8; mbi.RegionSize];
                    let mut bytes_read: usize = 0;

                    let ok = ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buf.as_mut_ptr() as *mut _,
                        mbi.RegionSize,
                        &mut bytes_read,
                    );

                    if ok != 0 && bytes_read > 0 {
                        let buf = &buf[..bytes_read];
                        total_scanned += bytes_read as u64;

                        let findings = scanner.scan_bytes(buf, &format!("pid:{}", pid));
                        for f in findings {
                            if found_patterns.insert(f.description.clone()) {
                                if verbose {
                                    eprintln!(
                                        "[memory] signature in memory: pid={} name={} {}",
                                        pid, proc_name, f.description
                                    );
                                }
                                pending_findings.push(Finding::new(
                                    "memory",
                                    format!("In-memory: {}", f.description),
                                    f.tier,
                                    format!(
                                        "pid={} name={} addr={:#x} size={}",
                                        pid,
                                        proc_name,
                                        mbi.BaseAddress as usize,
                                        mbi.RegionSize
                                    ),
                                ));
                            }
                        }
                    }
                }
            }

            // Advance to next region
            address = mbi.BaseAddress as usize + mbi.RegionSize;
            if address == 0 {
                break; // overflow protection
            }
        }

        // Only report findings if 3+ unique matches (same threshold as Linux)
        if pending_findings.len() >= 3 {
            for f in pending_findings {
                result.add_finding(f);
            }
            // Thread analysis only worth doing for suspect processes
            check_thread_start_addresses(result, handle, pid, proc_name, verbose);
        } else if verbose && !pending_findings.is_empty() {
            eprintln!(
                "[memory] pid={} name={}: {} match(es) below threshold, suppressed",
                pid, proc_name, pending_findings.len()
            );
        }

        CloseHandle(handle);
    }
}

/// Check if any thread in the process has a start address in private (non-image) memory.
#[cfg(windows)]
unsafe fn check_thread_start_addresses(
    result: &mut ScanResult,
    process_handle: windows_sys::Win32::Foundation::HANDLE,
    pid: u32,
    proc_name: &str,
    verbose: bool,
) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows_sys::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
    use windows_sys::Win32::System::Threading::{
        OpenThread, THREAD_QUERY_INFORMATION,
    };

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return;
    }

    let mut te: THREADENTRY32 = std::mem::zeroed();
    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut found_suspicious_thread = false;

    if Thread32First(snap, &mut te) != 0 {
        loop {
            if te.th32OwnerProcessID == pid && !found_suspicious_thread {
                let thread_handle = OpenThread(THREAD_QUERY_INFORMATION, 0, te.th32ThreadID);
                if !thread_handle.is_null() {
                    // NtQueryInformationThread to get start address
                    // ThreadQuerySetWin32StartAddress = 9
                    let mut start_addr: usize = 0;
                    let mut return_len: u32 = 0;

                    type NtQueryInformationThreadFn = unsafe extern "system" fn(
                        *mut std::ffi::c_void, u32, *mut std::ffi::c_void, u32, *mut u32,
                    ) -> i32;

                    let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(
                        b"ntdll.dll\0".as_ptr(),
                    );
                    if !ntdll.is_null() {
                        let func = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                            ntdll,
                            b"NtQueryInformationThread\0".as_ptr(),
                        );
                        if let Some(func) = func {
                            let query: NtQueryInformationThreadFn = std::mem::transmute(func);
                            let status = query(
                                thread_handle,
                                9, // ThreadQuerySetWin32StartAddress
                                &mut start_addr as *mut _ as *mut _,
                                std::mem::size_of::<usize>() as u32,
                                &mut return_len,
                            );

                            if status == 0 && start_addr != 0 {
                                // Check if start address is in MEM_IMAGE or MEM_PRIVATE
                                let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                                let ret = VirtualQueryEx(
                                    process_handle,
                                    start_addr as *const _,
                                    &mut mbi,
                                    std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                                );

                                if ret != 0 && mbi.Type != MEM_IMAGE {
                                    found_suspicious_thread = true;
                                    if verbose {
                                        eprintln!(
                                            "[memory] thread from private mem: pid={} tid={} addr={:#x}",
                                            pid, te.th32ThreadID, start_addr
                                        );
                                    }
                                    result.add_finding(Finding::new(
                                        "memory",
                                        "Thread start address in non-image memory (possible injection)",
                                        Tier::Tier2,
                                        format!(
                                            "pid={} name={} tid={} start_addr={:#x} mem_type={:#x}",
                                            pid, proc_name, te.th32ThreadID, start_addr, mbi.Type
                                        ),
                                    ));
                                }
                            }
                        }
                    }

                    CloseHandle(thread_handle);
                }
            }

            if Thread32Next(snap, &mut te) == 0 {
                break;
            }
        }
    }

    CloseHandle(snap);
}
