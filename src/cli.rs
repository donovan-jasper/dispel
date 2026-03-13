use clap::{Parser, Subcommand};
use realm_detect::Layer;

/// Realm C2 detection tool for CCDC blue team operations.
#[derive(Debug, Parser)]
#[command(name = "realm-detect", version, about)]
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

        /// Path to allowlist file (YAML or JSON).
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

        /// Path to allowlist file (YAML or JSON).
        #[arg(long)]
        allowlist: Option<String>,
    },
}

impl Cli {
    /// Dispatch to the appropriate subcommand handler.
    pub fn run(&self) -> anyhow::Result<i32> {
        match &self.command {
            Command::Scan { layer, json, allowlist } => {
                run_scan(layer.as_ref(), *json, allowlist.as_deref(), self.verbose)
            }
            Command::Watch { layer, interval, baseline, json, allowlist } => {
                run_watch(
                    layer.as_ref(),
                    *interval,
                    baseline.as_deref(),
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
    _allowlist: Option<&str>,
    verbose: bool,
) -> anyhow::Result<i32> {
    use realm_detect::output;
    use realm_detect::scan;
    use realm_detect::{Layer, ScanResult};

    let mut result = ScanResult::new();

    let run_all = layer.is_none();

    if run_all || matches!(layer, Some(Layer::Proc)) {
        result.merge(scan::proc::scan(verbose));
    }

    if run_all || matches!(layer, Some(Layer::Net)) {
        // TODO: scan::net::scan(verbose)
    }

    if run_all || matches!(layer, Some(Layer::Persist)) {
        // TODO: scan::persist::scan(verbose)
    }

    if run_all || matches!(layer, Some(Layer::Behavior)) {
        // TODO: scan::behavior::scan(verbose)
    }

    if json {
        output::json::print_result(&result);
    } else {
        output::human::print_result(&result);
    }

    Ok(result.exit_code())
}

fn run_watch(
    _layer: Option<&Layer>,
    _interval: u64,
    _baseline: Option<&str>,
    _json: bool,
    _allowlist: Option<&str>,
    _verbose: bool,
) -> anyhow::Result<i32> {
    println!("Watch mode not yet implemented");
    Ok(3)
}
