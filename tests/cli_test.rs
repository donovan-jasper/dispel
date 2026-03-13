use clap::Parser;
use realm_detect::Layer;

// Import the CLI from the binary's module via a re-export.
// We test CLI parsing independently of running the actual scan.

/// Minimal re-implementation of the Cli struct so we can test parsing
/// without executing side effects. We parse with clap then inspect fields.
///
/// Actually, we test via clap's try_parse_from to verify argument parsing.

#[derive(Debug, clap::Parser)]
#[command(name = "realm-detect")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    Scan {
        #[arg(short, long, value_enum)]
        layer: Option<Layer>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allowlist: Option<String>,
    },
    Watch {
        #[arg(short, long, value_enum)]
        layer: Option<Layer>,
        #[arg(short, long, default_value_t = 10)]
        interval: u64,
        #[arg(long)]
        baseline: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        allowlist: Option<String>,
    },
}

#[test]
fn test_parse_scan_no_args() {
    let cli = Cli::try_parse_from(["realm-detect", "scan"]).unwrap();
    assert!(!cli.verbose);
    let Command::Scan { layer, json, allowlist } = cli.command else {
        panic!("Expected Scan command");
    };
    assert!(layer.is_none());
    assert!(!json);
    assert!(allowlist.is_none());
}

#[test]
fn test_parse_scan_proc_layer() {
    let cli = Cli::try_parse_from(["realm-detect", "scan", "--layer", "proc"]).unwrap();
    let Command::Scan { layer, .. } = cli.command else { panic!() };
    assert_eq!(layer, Some(Layer::Proc));
}

#[test]
fn test_parse_scan_json_flag() {
    let cli = Cli::try_parse_from(["realm-detect", "scan", "--json"]).unwrap();
    let Command::Scan { json, .. } = cli.command else { panic!() };
    assert!(json);
}

#[test]
fn test_parse_watch_defaults() {
    let cli = Cli::try_parse_from(["realm-detect", "watch"]).unwrap();
    let Command::Watch { interval, layer, baseline, json, allowlist } = cli.command else {
        panic!("Expected Watch command");
    };
    assert_eq!(interval, 10);
    assert!(layer.is_none());
    assert!(baseline.is_none());
    assert!(!json);
    assert!(allowlist.is_none());
}

#[test]
fn test_parse_watch_interval() {
    let cli = Cli::try_parse_from(["realm-detect", "watch", "--interval", "30"]).unwrap();
    let Command::Watch { interval, .. } = cli.command else { panic!() };
    assert_eq!(interval, 30);
}

#[test]
fn test_parse_watch_baseline() {
    let cli = Cli::try_parse_from(["realm-detect", "watch", "--baseline", "/tmp/baseline.json"]).unwrap();
    let Command::Watch { baseline, .. } = cli.command else { panic!() };
    assert_eq!(baseline.as_deref(), Some("/tmp/baseline.json"));
}

#[test]
fn test_parse_verbose_flag() {
    let cli = Cli::try_parse_from(["realm-detect", "--verbose", "scan"]).unwrap();
    assert!(cli.verbose);
}

#[test]
fn test_parse_allowlist_flag() {
    let cli = Cli::try_parse_from(["realm-detect", "scan", "--allowlist", "/etc/realm-detect/allow.json"]).unwrap();
    let Command::Scan { allowlist, .. } = cli.command else { panic!() };
    assert_eq!(allowlist.as_deref(), Some("/etc/realm-detect/allow.json"));
}
