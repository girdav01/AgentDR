//! CoSAI ADR Agent — AI Detection & Response endpoint monitor.
//!
//! Rust implementation of the CoSAI ADR agent. Monitors processes, files, and
//! network connections for AI agent activity. Emits OCSF Category 7 events
//! and runs 20 detection rules including OpenClaw/general-agent threat detection.

mod config;
mod detectors;
mod engine;
mod integrity;
mod models;
mod monitors;
mod storage;

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "adr-agent", version, about = "CoSAI ADR Agent — AI Detection & Response")]
struct Args {
    /// Root directory for agent data (config, logs, runtime).
    #[arg(short, long, default_value = ".")]
    root: PathBuf,

    /// Path to config file (TOML). Defaults to <root>/config.toml.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Disable stdout streaming of events.
    #[arg(long, default_value_t = false)]
    quiet: bool,

    /// Watch directories (can be repeated). Overrides config file.
    #[arg(short, long)]
    watch: Vec<String>,

    /// Download and verify updated community detection rules, then exit.
    #[arg(long, default_value_t = false)]
    update: bool,

    /// Verify integrity of local community rules, then exit.
    #[arg(long, default_value_t = false)]
    verify: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Init tracing
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("adr_agent=info".parse().unwrap()))
        .with_target(false)
        .init();

    // ── Handle --verify: check integrity and exit ──
    if args.verify {
        let ri = integrity::RuleIntegrity::discover();
        let status = ri.status();
        println!("{}", serde_json::to_string_pretty(&status).unwrap());
        if status.integrity == "ok" {
            println!("\n✓  All rule files verified successfully.");
        } else {
            println!("\n⚠  Integrity check FAILED — rules may have been tampered with.");
            std::process::exit(1);
        }
        return;
    }

    // ── Handle --update: download, verify, and replace rules, then exit ──
    if args.update {
        let ri = integrity::RuleIntegrity::discover();
        let result = ri.update(true);
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        if result.status == "integrity_failed" || result.status == "error" {
            std::process::exit(1);
        }
        return;
    }

    // ── Normal agent startup ──

    // Startup integrity check
    let ri = integrity::RuleIntegrity::discover();
    match ri.verify() {
        Ok(status) => tracing::info!(version = %status.version, "Community rules integrity check passed"),
        Err(msg) => {
            tracing::warn!("Community rules integrity issue: {}", msg);
            tracing::info!("Attempting automatic rule update...");
            let result = ri.update(false);
            tracing::info!(status = %result.status, "Auto-update result");
        }
    }

    // Load config
    let config_path = args.config.unwrap_or_else(|| args.root.join("config.toml"));
    let mut cfg = config::Config::load(&config_path);

    // CLI overrides
    if !args.watch.is_empty() {
        cfg.watch_directories = args.watch;
    }

    tracing::info!(
        root = %args.root.display(),
        watch_dirs = ?cfg.watch_directories,
        detection_rules = 20,
        agent_signatures = 39,
        "CoSAI ADR Agent v{} (Rust) — CoSAI OCSF Category 7",
        env!("CARGO_PKG_VERSION"),
    );

    // Run
    let engine = engine::AgentEngine::new(args.root, cfg, !args.quiet);
    engine.run().await;
}
