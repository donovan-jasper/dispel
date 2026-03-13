//! Remediation module: detect, quarantine, and remove Realm C2 implants.
//!
//! This module is the backend for `dispel kill`. It:
//!   1. Runs the proc scan to detect implants
//!   2. Generates an IR report for context
//!   3. For each detected implant: quarantines the binary, kills PIDs,
//!      removes the binary, and scrubs persistence artifacts

use std::path::PathBuf;
#[cfg(any(target_os = "linux", windows))]
use std::path::Path;

// ANSI color helpers — no dep needed
fn green(s: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}
fn red(s: &str) -> String {
    format!("\x1b[31m{}\x1b[0m", s)
}
fn yellow(s: &str) -> String {
    format!("\x1b[33m{}\x1b[0m", s)
}

/// Configuration for a kill run.
pub struct KillConfig {
    pub dry_run: bool,
    pub quarantine_dir: PathBuf,
    pub verbose: bool,
}

impl KillConfig {
    pub fn new(dry_run: bool, quarantine_dir: Option<PathBuf>, verbose: bool) -> Self {
        let qdir = quarantine_dir.unwrap_or_else(|| {
            #[cfg(windows)]
            {
                PathBuf::from(r"C:\ProgramData\dispel\quarantine")
            }
            #[cfg(not(windows))]
            {
                PathBuf::from("/var/lib/dispel/quarantine")
            }
        });
        Self { dry_run, quarantine_dir: qdir, verbose }
    }
}

/// Entry point for `dispel kill`.
/// Returns an exit code: 0 = clean, 2 = implants found/killed, 3 = error.
pub fn run_kill(cfg: &KillConfig) -> anyhow::Result<i32> {
    #[cfg(target_os = "linux")]
    {
        return run_kill_linux(cfg);
    }

    #[cfg(windows)]
    {
        return run_kill_windows(cfg);
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = cfg;
        eprintln!("{}", red("Kill command is only supported on Linux and Windows."));
        return Ok(1);
    }
}

#[cfg(target_os = "linux")]
fn run_kill_linux(cfg: &KillConfig) -> anyhow::Result<i32> {
    use crate::ir::generate_report;
    use crate::scan;
    use crate::Severity;

    // Step 1: run proc scan
    let result = scan::proc::scan(cfg.verbose);

    if result.severity == Severity::Clean {
        println!("{}", green("No Realm C2 implants detected."));
        return Ok(0);
    }

    // Step 2: generate IR report for forensic context
    let report = generate_report(&result);

    if report.implants.is_empty() {
        // Findings exist but no resolved implant paths — print findings and exit
        println!(
            "{} {} finding(s), but no binary paths resolved. Manual investigation required.",
            yellow("WARNING:"),
            result.findings.len()
        );
        for f in &result.findings {
            println!("  [{}] {} — {}", f.tier.label(), f.description, f.detail);
        }
        return Ok(2);
    }

    println!(
        "{} {} Realm C2 implant(s) detected.",
        red("DETECTED:"),
        report.implants.len()
    );
    if cfg.dry_run {
        println!("{}", yellow("DRY RUN — no changes will be made."));
    }
    println!();

    // Step 3: act on each implant
    for implant in &report.implants {
        println!("--- {}", implant.summary_line());
        println!();

        let pids: Vec<u32> = implant.processes.iter().map(|p| p.pid).collect();

        // a) Quarantine
        quarantine_binary(cfg, &implant.path, &pids);

        // b) Kill processes
        kill_processes(cfg, &pids, &implant.path);

        // c) Remove binary
        remove_binary(cfg, &implant.path);

        // d) Remove persistence
        remove_persistence(cfg);

        println!();
    }

    Ok(2)
}

/// Copy the implant binary to the quarantine directory before destruction.
/// Falls back to /proc/<pid>/exe if the file is already gone from disk.
#[cfg(target_os = "linux")]
fn quarantine_binary(cfg: &KillConfig, binary_path: &str, pids: &[u32]) {
    use sha2::{Digest, Sha256};
    use std::fs;

    // Determine source path — prefer the real file, fall back to /proc/<pid>/exe
    let source = if Path::new(binary_path).exists() {
        binary_path.to_string()
    } else if let Some(&pid) = pids.first() {
        let proc_exe = format!("/proc/{}/exe", pid);
        if Path::new(&proc_exe).exists() {
            if cfg.verbose {
                eprintln!("[quarantine] Binary deleted from disk, using {}", proc_exe);
            }
            proc_exe
        } else {
            println!(
                "  {} quarantine: binary not on disk and no /proc/exe available ({})",
                red("SKIP"),
                binary_path
            );
            return;
        }
    } else {
        println!(
            "  {} quarantine: binary not found and no PIDs to fall back to ({})",
            red("SKIP"),
            binary_path
        );
        return;
    };

    // Compute sha256 for the quarantine filename
    let hash = match fs::read(&source) {
        Ok(data) => {
            let mut h = Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        }
        Err(e) => {
            println!(
                "  {} quarantine: cannot read {} — {}",
                red("ERROR"),
                source,
                e
            );
            return;
        }
    };

    let basename = Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dest_name = format!("{}_{}", &hash[..16], basename);
    let dest = cfg.quarantine_dir.join(&dest_name);

    if cfg.dry_run {
        println!(
            "  {} would quarantine {} -> {}",
            yellow("DRY-RUN"),
            source,
            dest.display()
        );
        return;
    }

    // Create quarantine directory if it doesn't exist
    if let Err(e) = fs::create_dir_all(&cfg.quarantine_dir) {
        println!(
            "  {} quarantine: cannot create dir {} — {}",
            red("ERROR"),
            cfg.quarantine_dir.display(),
            e
        );
        return;
    }

    match fs::copy(&source, &dest) {
        Ok(bytes) => println!(
            "  {} quarantined {} -> {} ({} bytes)",
            green("OK"),
            source,
            dest.display(),
            bytes
        ),
        Err(e) => println!(
            "  {} quarantine: copy failed {} -> {} — {}",
            red("ERROR"),
            source,
            dest.display(),
            e
        ),
    }
}

/// Send SIGKILL to all PIDs associated with the implant.
#[cfg(target_os = "linux")]
fn kill_processes(cfg: &KillConfig, pids: &[u32], binary_path: &str) {
    if pids.is_empty() {
        println!(
            "  {} no live PIDs found for {}",
            yellow("NOTE"),
            binary_path
        );
        return;
    }

    for &pid in pids {
        if cfg.dry_run {
            println!(
                "  {} would SIGKILL PID {}",
                yellow("DRY-RUN"),
                pid
            );
            continue;
        }

        // SAFETY: kill(2) with SIGKILL — standard Unix operation
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret == 0 {
            println!("  {} SIGKILL -> PID {}", green("OK"), pid);
        } else {
            let err = std::io::Error::last_os_error();
            println!("  {} kill PID {} — {}", red("ERROR"), pid, err);
        }
    }
}

/// Delete the implant binary from disk.
#[cfg(target_os = "linux")]
fn remove_binary(cfg: &KillConfig, binary_path: &str) {
    let p = Path::new(binary_path);

    if !p.exists() {
        println!("  {} binary already gone: {}", yellow("NOTE"), binary_path);
        return;
    }

    if cfg.dry_run {
        println!("  {} would delete {}", yellow("DRY-RUN"), binary_path);
        return;
    }

    match std::fs::remove_file(p) {
        Ok(()) => println!("  {} deleted {}", green("OK"), binary_path),
        Err(e) => println!("  {} delete {} — {}", red("ERROR"), binary_path, e),
    }
}

/// Remove persistence artifacts: beacon ID files, systemd units, sysvinit script.
#[cfg(target_os = "linux")]
fn remove_persistence(cfg: &KillConfig) {
    use crate::signatures::strings::{BEACON_ID_PATHS_LINUX, SYSTEMD_PATHS, SYSVINIT_PATH};

    // Beacon ID files
    for path in BEACON_ID_PATHS_LINUX {
        remove_file_if_exists(cfg, path, "beacon ID file");
    }

    // Systemd unit files
    let mut removed_systemd = false;
    for path in SYSTEMD_PATHS {
        if remove_file_if_exists(cfg, path, "systemd unit") {
            removed_systemd = true;
        }
    }

    if removed_systemd || cfg.dry_run {
        reload_systemd(cfg);
    }

    // SysV init script
    remove_file_if_exists(cfg, SYSVINIT_PATH, "sysvinit script");
}

/// Delete a file if it exists. Returns true if the file existed and was removed (or would be).
#[cfg(target_os = "linux")]
fn remove_file_if_exists(cfg: &KillConfig, path: &str, label: &str) -> bool {
    if !Path::new(path).exists() {
        return false;
    }

    if cfg.dry_run {
        println!("  {} would delete {} ({})", yellow("DRY-RUN"), path, label);
        return true;
    }

    match std::fs::remove_file(path) {
        Ok(()) => {
            println!("  {} deleted {} ({})", green("OK"), path, label);
            true
        }
        Err(e) => {
            println!("  {} delete {} ({}) — {}", red("ERROR"), path, label, e);
            false
        }
    }
}

/// Run `systemctl daemon-reload` after removing systemd units.
#[cfg(target_os = "linux")]
fn reload_systemd(cfg: &KillConfig) {
    if cfg.dry_run {
        println!("  {} would run: systemctl daemon-reload", yellow("DRY-RUN"));
        return;
    }

    match std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .status()
    {
        Ok(status) if status.success() => {
            println!("  {} systemctl daemon-reload", green("OK"));
        }
        Ok(status) => {
            println!(
                "  {} systemctl daemon-reload exited with status {}",
                yellow("WARN"),
                status
            );
        }
        Err(e) => {
            println!(
                "  {} systemctl daemon-reload — {} (systemd may not be present)",
                yellow("WARN"),
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Windows kill implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn run_kill_windows(cfg: &KillConfig) -> anyhow::Result<i32> {
    use crate::ir::generate_report;
    use crate::scan;
    use crate::Severity;

    // Step 1: run proc scan
    let result = scan::proc::scan(cfg.verbose);

    if result.severity == Severity::Clean {
        println!("{}", green("No Realm C2 implants detected."));
        return Ok(0);
    }

    // Step 2: generate IR report for forensic context
    let report = generate_report(&result);

    if report.implants.is_empty() {
        println!(
            "{} {} finding(s), but no binary paths resolved. Manual investigation required.",
            yellow("WARNING:"),
            result.findings.len()
        );
        for f in &result.findings {
            println!("  [{}] {} — {}", f.tier.label(), f.description, f.detail);
        }
        return Ok(2);
    }

    println!(
        "{} {} Realm C2 implant(s) detected.",
        red("DETECTED:"),
        report.implants.len()
    );
    if cfg.dry_run {
        println!("{}", yellow("DRY RUN — no changes will be made."));
    }
    println!();

    // Step 3: act on each implant
    for implant in &report.implants {
        println!("--- {}", implant.summary_line());
        println!();

        let pids: Vec<u32> = implant.processes.iter().map(|p| p.pid).collect();

        // a) Quarantine
        quarantine_binary_windows(cfg, &implant.path);

        // b) Terminate processes
        terminate_processes_windows(cfg, &pids, &implant.path);

        // c) Remove binary
        remove_binary_windows(cfg, &implant.path);

        // d) Remove persistence
        remove_persistence_windows(cfg);

        println!();
    }

    Ok(2)
}

/// Copy the implant binary to the quarantine directory on Windows.
#[cfg(windows)]
fn quarantine_binary_windows(cfg: &KillConfig, binary_path: &str) {
    use sha2::{Digest, Sha256};
    use std::fs;

    if !Path::new(binary_path).exists() {
        println!(
            "  {} quarantine: binary not found on disk ({})",
            red("SKIP"),
            binary_path
        );
        return;
    }

    // Compute sha256 for the quarantine filename
    let hash = match fs::read(binary_path) {
        Ok(data) => {
            let mut h = Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        }
        Err(e) => {
            println!(
                "  {} quarantine: cannot read {} — {}",
                red("ERROR"),
                binary_path,
                e
            );
            return;
        }
    };

    let basename = Path::new(binary_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dest_name = format!("{}_{}", &hash[..16], basename);
    let dest = cfg.quarantine_dir.join(&dest_name);

    if cfg.dry_run {
        println!(
            "  {} would quarantine {} -> {}",
            yellow("DRY-RUN"),
            binary_path,
            dest.display()
        );
        return;
    }

    if let Err(e) = fs::create_dir_all(&cfg.quarantine_dir) {
        println!(
            "  {} quarantine: cannot create dir {} — {}",
            red("ERROR"),
            cfg.quarantine_dir.display(),
            e
        );
        return;
    }

    match fs::copy(binary_path, &dest) {
        Ok(bytes) => println!(
            "  {} quarantined {} -> {} ({} bytes)",
            green("OK"),
            binary_path,
            dest.display(),
            bytes
        ),
        Err(e) => println!(
            "  {} quarantine: copy failed {} -> {} — {}",
            red("ERROR"),
            binary_path,
            dest.display(),
            e
        ),
    }
}

/// Terminate processes on Windows using TerminateProcess via windows-sys.
#[cfg(windows)]
fn terminate_processes_windows(cfg: &KillConfig, pids: &[u32], binary_path: &str) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_TERMINATE,
    };

    if pids.is_empty() {
        println!(
            "  {} no live PIDs found for {}",
            yellow("NOTE"),
            binary_path
        );
        return;
    }

    for &pid in pids {
        if cfg.dry_run {
            println!(
                "  {} would TerminateProcess PID {}",
                yellow("DRY-RUN"),
                pid
            );
            continue;
        }

        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if handle.is_null() {
                let err = std::io::Error::last_os_error();
                println!("  {} OpenProcess PID {} — {}", red("ERROR"), pid, err);
                continue;
            }

            let ret = TerminateProcess(handle, 1);
            CloseHandle(handle);

            if ret != 0 {
                println!("  {} TerminateProcess -> PID {}", green("OK"), pid);
            } else {
                let err = std::io::Error::last_os_error();
                println!("  {} TerminateProcess PID {} — {}", red("ERROR"), pid, err);
            }
        }
    }
}

/// Delete the implant binary from disk on Windows.
#[cfg(windows)]
fn remove_binary_windows(cfg: &KillConfig, binary_path: &str) {
    let p = Path::new(binary_path);

    if !p.exists() {
        println!("  {} binary already gone: {}", yellow("NOTE"), binary_path);
        return;
    }

    if cfg.dry_run {
        println!("  {} would delete {}", yellow("DRY-RUN"), binary_path);
        return;
    }

    match std::fs::remove_file(p) {
        Ok(()) => println!("  {} deleted {}", green("OK"), binary_path),
        Err(e) => println!("  {} delete {} — {}", red("ERROR"), binary_path, e),
    }
}

/// Remove persistence artifacts on Windows: registry keys, services, beacon ID files.
#[cfg(windows)]
fn remove_persistence_windows(cfg: &KillConfig) {
    use crate::signatures::strings::{BEACON_ID_PATHS_WINDOWS, TIER1_SERVICE_NAMES};

    // 1. Delete registry key HKLM\SOFTWARE\Imix
    remove_registry_key_windows(cfg, r"SOFTWARE\Imix");

    // 2. Stop and delete Windows services
    for svc_name in TIER1_SERVICE_NAMES {
        stop_and_delete_service_windows(cfg, svc_name);
    }

    // 3. Remove beacon ID files
    for path in BEACON_ID_PATHS_WINDOWS {
        remove_file_if_exists_windows(cfg, path, "beacon ID file");
    }
}

/// Delete a registry key using reg.exe.
#[cfg(windows)]
fn remove_registry_key_windows(cfg: &KillConfig, subkey: &str) {
    use std::process::Command;

    let full_key = format!(r"HKLM\{}", subkey);

    // Check if the key exists first
    let query = Command::new("reg.exe")
        .args(["query", &full_key])
        .output();

    let exists = match query {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    if !exists {
        return;
    }

    if cfg.dry_run {
        println!(
            "  {} would delete registry key {}",
            yellow("DRY-RUN"),
            full_key
        );
        return;
    }

    match Command::new("reg.exe")
        .args(["delete", &full_key, "/f"])
        .status()
    {
        Ok(status) if status.success() => {
            println!("  {} deleted registry key {}", green("OK"), full_key);
        }
        Ok(status) => {
            println!(
                "  {} delete registry key {} — exited with {}",
                red("ERROR"),
                full_key,
                status
            );
        }
        Err(e) => {
            println!(
                "  {} delete registry key {} — {}",
                red("ERROR"),
                full_key,
                e
            );
        }
    }
}

/// Stop and delete a Windows service using sc.exe.
#[cfg(windows)]
fn stop_and_delete_service_windows(cfg: &KillConfig, svc_name: &str) {
    use std::process::Command;

    // Check if the service exists
    let query = Command::new("sc.exe")
        .args(["query", svc_name])
        .output();

    let exists = match query {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.contains("RUNNING")
                || stdout.contains("STOPPED")
                || stdout.contains("PAUSED")
                || stdout.contains("START_PENDING")
                || stdout.contains("STOP_PENDING")
        }
        Err(_) => false,
    };

    if !exists {
        return;
    }

    if cfg.dry_run {
        println!(
            "  {} would stop and delete service '{}'",
            yellow("DRY-RUN"),
            svc_name
        );
        return;
    }

    // Stop the service (ignore errors — it may already be stopped)
    let stop_result = Command::new("sc.exe")
        .args(["stop", svc_name])
        .output();

    match stop_result {
        Ok(out) if out.status.success() => {
            println!("  {} stopped service '{}'", green("OK"), svc_name);
        }
        Ok(_) => {
            // Service might already be stopped, that's fine
            if cfg.verbose {
                eprintln!("[remediate] sc.exe stop {} returned non-zero (may already be stopped)", svc_name);
            }
        }
        Err(e) => {
            println!("  {} stop service '{}' — {}", yellow("WARN"), svc_name, e);
        }
    }

    // Delete the service
    match Command::new("sc.exe")
        .args(["delete", svc_name])
        .status()
    {
        Ok(status) if status.success() => {
            println!("  {} deleted service '{}'", green("OK"), svc_name);
        }
        Ok(status) => {
            println!(
                "  {} delete service '{}' — exited with {}",
                red("ERROR"),
                svc_name,
                status
            );
        }
        Err(e) => {
            println!(
                "  {} delete service '{}' — {}",
                red("ERROR"),
                svc_name,
                e
            );
        }
    }
}

/// Delete a file if it exists on Windows.
#[cfg(windows)]
fn remove_file_if_exists_windows(cfg: &KillConfig, path: &str, label: &str) -> bool {
    if !Path::new(path).exists() {
        return false;
    }

    if cfg.dry_run {
        println!("  {} would delete {} ({})", yellow("DRY-RUN"), path, label);
        return true;
    }

    match std::fs::remove_file(path) {
        Ok(()) => {
            println!("  {} deleted {} ({})", green("OK"), path, label);
            true
        }
        Err(e) => {
            println!("  {} delete {} ({}) — {}", red("ERROR"), path, label, e);
            false
        }
    }
}
