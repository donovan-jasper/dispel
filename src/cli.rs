use clap::{Parser, Subcommand};
use dispel::Layer;

/// Realm C2 detection tool for CCDC blue team operations.
#[derive(Debug, Parser)]
#[command(name = "dispel", version, about)]
pub struct Cli {
    /// Enable verbose output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan the system for Realm C2 indicators.
    Scan {
        /// Limit scan to a specific layer (default: all layers).
        #[arg(short, long, value_enum)]
        layer: Option<Layer>,

        /// Output results as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// Generate an incident response report with forensic details.
        #[arg(long)]
        ir: bool,

        /// Path to allowlist file.
        #[arg(long)]
        allowlist: Option<String>,
    },

    /// Watch mode: continuously monitor for Realm C2 indicators.
    Watch {
        /// Limit watch to a specific layer (default: all layers).
        #[arg(short, long, value_enum)]
        layer: Option<Layer>,

        /// Polling interval in seconds.
        #[arg(short, long, default_value_t = 10)]
        interval: u64,

        /// Path to baseline file (JSON) to diff against.
        #[arg(long)]
        baseline: Option<String>,

        /// Output alerts as JSON lines instead of human-readable text.
        #[arg(long)]
        json: bool,

        /// Path to allowlist file.
        #[arg(long)]
        allowlist: Option<String>,
    },
}

impl Cli {
    /// Dispatch to the appropriate subcommand handler.
    pub fn run(&self) -> anyhow::Result<i32> {
        match &self.command {
            Command::Scan { layer, json, ir, allowlist } => {
                run_scan(layer.as_ref(), *json, *ir, allowlist.as_deref(), self.verbose)
            }
            Command::Watch { layer, interval, baseline, json, allowlist } => {
                let baseline_secs = baseline.as_deref().and_then(|b| b.parse::<u64>().ok());
                run_watch(
                    layer.as_ref(),
                    *interval,
                    baseline_secs,
                    *json,
                    allowlist.as_deref(),
                    self.verbose,
                )
            }
        }
    }
}

fn run_scan(
    layer: Option<&Layer>,
    json: bool,
    ir: bool,
    allowlist_path: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    use dispel::allowlist::Allowlist;
    use dispel::output;
    use dispel::scan;
    use dispel::{Layer, ScanResult};

    let _allowlist = match allowlist_path {
        Some(path) => Allowlist::from_file(path)?,
        None => Allowlist::new(),
    };

    if verbose {
        eprintln!("[verbose] Starting scan, layer: {:?}", layer);
    }

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

    if json {
        if ir {
            let report = dispel::ir::generate_report(&result);
            let combined = serde_json::json!({
                "scan": result,
                "ir_report": report,
            });
            println!("{}", serde_json::to_string_pretty(&combined).unwrap_or_default());
        } else {
            output::json::print_result(&result);
        }
    } else {
        output::human::print_result(&result);
        if ir {
            let report = dispel::ir::generate_report(&result);
            output::human::print_ir_report(&report);
        }
    }

    Ok(result.exit_code())
}

fn run_watch(
    layer: Option<&Layer>,
    interval: u64,
    baseline: Option<u64>,
    json: bool,
    allowlist_path: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    use dispel::allowlist::Allowlist;
    use dispel::watch;

    let allowlist = match allowlist_path {
        Some(path) => Allowlist::from_file(path)?,
        None => Allowlist::new(),
    };

    watch::run(layer, interval, baseline, json, &allowlist, verbose)
}
