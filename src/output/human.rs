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

fn format_tier_label(tier: &Tier) -> colored::ColoredString {
    let label = format!("[{}]", tier.label());
    match tier {
        Tier::Tier1 => label.yellow().bold(),
        Tier::Tier2 => label.truecolor(255, 140, 0).bold(), // orange
        Tier::Tier3 => label.red().bold(),
        Tier::Behavioral => label.magenta().bold(),
    }
}
