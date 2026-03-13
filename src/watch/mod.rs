use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::allowlist::Allowlist;
use crate::Layer;
use crate::output::{human, json};
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
    _allowlist: &Allowlist,
    verbose: bool,
) -> anyhow::Result<i32> {
    let interval = Duration::from_secs(interval_secs);
    let mut dedup = DedupTracker::new();

    if !json_output {
        eprintln!("realm-detect watch mode (interval={}s, Ctrl+C to stop)", interval_secs);
    }

    if let Some(baseline) = baseline_secs {
        if !json_output {
            eprintln!("Baselining for {}s...", baseline);
        }
        std::thread::sleep(Duration::from_secs(baseline));
        let result = run_scan_layers(layer, verbose);
        for finding in &result.findings {
            dedup.should_report(finding);
        }
        if !json_output {
            eprintln!("Baseline complete. {} patterns learned. Monitoring...", dedup.seen.len());
        }
    }

    loop {
        let result = run_scan_layers(layer, verbose);

        for finding in &result.findings {
            if dedup.should_report(finding) {
                if json_output {
                    json::print_finding_line(finding);
                } else {
                    human::print_alert(finding);
                }
            }
        }

        dedup.cleanup();
        std::thread::sleep(interval);
    }
}

fn run_scan_layers(layer: Option<&Layer>, verbose: bool) -> ScanResult {
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

    result
}
