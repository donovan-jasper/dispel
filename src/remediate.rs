//! Remediation module: detect, quarantine, and remove Realm C2 implants.
//!
//! This module is the backend for `dispel kill`. It:
//!   1. Runs the proc scan to detect implants
//!   2. Generates an IR report for context
//!   3. For each detected implant: quarantines the binary, kills PIDs,
//!      removes the binary, and scrubs persistence artifacts

use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::path::Path;

// ANSI color helpers — no dep needed
#[cfg(target_os = "linux")]
fn green(s: &str) -> String {
    format!("\x1b[32m{}\x1b[0m", s)
}
fn red(s: &str) -> String {
    format!("\x1b[31m{}\x1b[0m", s)
}
#[cfg(target_os = "linux")]
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
        let qdir = quarantine_dir
            .unwrap_or_else(|| PathBuf::from("/var/lib/dispel/quarantine"));
        Self { dry_run, quarantine_dir: qdir, verbose }
    }
}

/// Entry point for `dispel kill`.
/// Returns an exit code: 0 = clean, 2 = implants found/killed, 3 = error.
pub fn run_kill(cfg: &KillConfig) -> anyhow::Result<i32> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cfg;
        eprintln!("{}", red("Kill command is only supported on Linux."));
        return Ok(1);
    }

    #[cfg(target_os = "linux")]
    {
        run_kill_linux(cfg)
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
