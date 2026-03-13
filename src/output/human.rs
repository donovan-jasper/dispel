use colored::Colorize;
use crate::{Finding, ScanResult, Severity, Tier};

/// Print a full scan result to stdout with colored terminal formatting.
pub fn print_result(result: &ScanResult) {
    let header = match result.severity {
        Severity::Clean => "  CLEAN  ".on_green().black().bold(),
        Severity::Suspect => "  SUSPECT  ".on_yellow().black().bold(),
        Severity::Detected => "  DETECTED  ".on_red().white().bold(),
    };

    println!();
    println!("Status: {} (score: {})", header, result.score);
    println!();

    if result.findings.is_empty() {
        println!("  No indicators found.");
    } else {
        println!("Findings ({}):", result.findings.len());
        for finding in &result.findings {
            print_finding(finding);
        }
    }

    println!();
    println!(
        "Summary: {} finding(s), score {}, severity {}",
        result.findings.len(),
        result.score,
        result.severity.as_str()
    );
    println!();
}

/// Print a single finding with colored tier label.
pub fn print_finding(finding: &Finding) {
    let tier_label = format_tier_label(&finding.tier);
    println!(
        "  {} [{}] {} — {}",
        tier_label,
        finding.layer,
        finding.description,
        finding.detail.dimmed()
    );
}

/// Print a finding alert for watch mode, including a timestamp.
pub fn print_alert(finding: &Finding) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tier_label = format_tier_label(&finding.tier);
    println!(
        "[{}] ALERT {} [{}] {} — {}",
        now,
        tier_label,
        finding.layer,
        finding.description,
        finding.detail.dimmed()
    );
}

/// Print an IR report in human-readable format.
pub fn print_ir_report(report: &crate::ir::IrReport) {
    use crate::ir::IrReport;

    if report.implants.is_empty() {
        println!("  No implant binaries to report on.");
        return;
    }

    println!();
    println!("{}", "=== INCIDENT RESPONSE REPORT ===".bold());

    for (i, implant) in report.implants.iter().enumerate() {
        println!();
        println!(
            "{} {}",
            format!("--- Implant #{} ---", i + 1).red().bold(),
            implant.path.white().bold()
        );

        // File info
        if let Some(ref fi) = implant.file_info {
            println!();
            println!("  {}", "File Info:".cyan().bold());
            println!("    SHA256:      {}", fi.sha256.yellow());
            println!("    Size:        {} bytes", fi.size_bytes);
            println!("    Owner:       {}:{}", fi.owner, fi.group);
            println!("    Permissions: {}", fi.permissions);
            println!("    Modified:    {}", fi.modified);
            println!("    Accessed:    {}", fi.accessed);
            println!("    Created:     {}", fi.created);
        }

        // Processes
        if !implant.processes.is_empty() {
            println!();
            println!("  {}", "Running Processes:".cyan().bold());
            for proc in &implant.processes {
                println!("    PID {} (parent: {} [{}])",
                    proc.pid.to_string().yellow().bold(),
                    proc.parent_name,
                    proc.ppid);
                println!("      User:      {}", proc.user);
                println!("      Command:   {}", proc.cmdline.dimmed());
                println!("      CWD:       {}", proc.cwd);
                println!("      Started:   {}", proc.start_time);
                if !proc.env_vars.is_empty() {
                    println!("      Env:");
                    for var in &proc.env_vars {
                        println!("        {}", var.dimmed());
                    }
                }
            }
        }

        // Network connections
        if !implant.connections.is_empty() {
            println!();
            println!("  {}", "Network Connections:".cyan().bold());
            for conn in &implant.connections {
                let state_colored = match conn.state.as_str() {
                    "ESTABLISHED" => conn.state.green().to_string(),
                    "SYN_SENT" => conn.state.yellow().to_string(),
                    "LISTEN" => conn.state.blue().to_string(),
                    _ => conn.state.clone(),
                };
                println!(
                    "    {} {} -> {} (pid {})",
                    state_colored,
                    conn.local_addr.dimmed(),
                    conn.remote_addr.white().bold(),
                    conn.pid
                );
            }
        } else {
            println!();
            println!("  {}", "Network Connections:".cyan().bold());
            println!("    (none found — binary may be dormant or connections already closed)");
        }

        // Persistence
        if !implant.persistence.is_empty() {
            println!();
            println!("  {}", "Persistence:".cyan().bold());
            for p in &implant.persistence {
                println!("    {} — {}", p.mechanism, p.path.dimmed());
            }
        }
    }

    println!();
    println!("{}", "================================".bold());
    println!();
}

fn format_tier_label(tier: &Tier) -> colored::ColoredString {
    let label = format!("[{}]", tier.label());
    match tier {
        Tier::Tier1 => label.yellow().bold(),
        Tier::Tier2 => label.truecolor(255, 140, 0).bold(), // orange
        Tier::Tier3 => label.red().bold(),
        Tier::Behavioral => label.magenta().bold(),
    }
}
