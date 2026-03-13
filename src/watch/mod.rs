use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::allowlist::Allowlist;
use crate::Layer;
use crate::output::{human, json, syslog};
use crate::{scan, Finding, ScanResult};

struct DedupTracker {
    seen: HashMap<String, (Instant, Instant, u32)>,
    suppress_duration: Duration,
}

impl DedupTracker {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
            suppress_duration: Duration::from_secs(300),
        }
    }

    fn should_report(&mut self, finding: &Finding) -> bool {
        let key = finding.dedup_key();
        let now = Instant::now();

        if let Some((_, last_reported, _)) = self.seen.get(&key) {
            if now.duration_since(*last_reported) < self.suppress_duration {
                return false;
            }
        }

        self.seen.insert(key, (now, now, finding.tier.weight()));
        true
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.seen.retain(|_, (first_seen, _, _)| {
            now.duration_since(*first_seen) < self.suppress_duration * 2
        });
    }
}

pub fn run(
    layer: Option<&Layer>,
    interval_secs: u64,
    baseline_secs: Option<u64>,
    json_output: bool,
    allowlist: &Allowlist,
    syslog_enabled: bool,
    webhook_url: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    let interval = Duration::from_secs(interval_secs);
    let mut dedup = DedupTracker::new();

    if !json_output {
        eprintln!("dispel watch mode (interval={}s, Ctrl+C to stop)", interval_secs);
    }

    if let Some(baseline) = baseline_secs {
        if !json_output {
            eprintln!("Baselining for {}s...", baseline);
        }
        std::thread::sleep(Duration::from_secs(baseline));
        let result = run_scan_layers(layer, verbose, false);
        for finding in &result.findings {
            dedup.should_report(finding);
        }
        if !json_output {
            eprintln!("Baseline complete. {} patterns learned. Monitoring...", dedup.seen.len());
        }
    }

    let mut memory_scan_counter: u64 = 0;
    const MEMORY_SCAN_EVERY: u64 = 6;

    loop {
        let skip_memory = memory_scan_counter % MEMORY_SCAN_EVERY != 0;
        memory_scan_counter += 1;

        let mut result = run_scan_layers(layer, verbose, skip_memory);
        result.filter(allowlist);

        for finding in &result.findings {
            if dedup.should_report(finding) {
                if json_output {
                    json::print_finding_line(finding);
                } else {
                    human::print_alert(finding);
                }
                if syslog_enabled {
                    syslog::send_to_syslog(finding);
                }
                if let Some(url) = webhook_url {
                    syslog::send_to_webhook(finding, url);
                }
            }
        }

        dedup.cleanup();
        std::thread::sleep(interval);
    }
}

fn run_scan_layers(layer: Option<&Layer>, verbose: bool, skip_memory: bool) -> ScanResult {
    let mut result = ScanResult::new();

    let run_all = layer.is_none();

    if run_all || matches!(layer, Some(Layer::Proc)) {
        result.merge(scan::proc::scan(verbose));
    }
    if run_all || matches!(layer, Some(Layer::Net)) {
        result.merge(scan::net::scan(verbose));
    }
    if run_all || matches!(layer, Some(Layer::Persist)) {
        result.merge(scan::persist::scan(verbose));
    }
    if run_all || matches!(layer, Some(Layer::Behavior)) {
        result.merge(scan::behavior::scan(verbose));
    }
    if !skip_memory && (run_all || matches!(layer, Some(Layer::Memory))) {
        result.merge(scan::memory::scan(verbose));
    }

    result
}
