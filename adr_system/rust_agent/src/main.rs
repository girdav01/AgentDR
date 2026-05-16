//! CoSAI ADR Agent — AI Detection & Response endpoint monitor.
//!
//! Rust implementation of the CoSAI ADR agent. Monitors processes, files, and
//! network connections for AI agent activity, ingests OpenTelemetry signals
//! from local AI runtimes (Claude Code, Codex CLI, Cursor, Aider), inventories
//! and wraps MCP servers, and emits OCSF Category 7 events.

mod config;
mod detectors;
mod engine;
mod hooks;
mod ingest;
mod integrity;
mod mcp;
mod models;
mod monitors;
mod storage;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "adr-agent", version, about = "CoSAI ADR Agent — AI Detection & Response")]
struct Cli {
    /// Root directory for agent data (config, logs, runtime).
    #[arg(short, long, default_value = ".", global = true)]
    root: PathBuf,

    /// Path to config file (TOML). Defaults to <root>/config.toml.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the agent (default).
    Start {
        /// Disable stdout streaming of events.
        #[arg(long, default_value_t = false)]
        quiet: bool,

        /// Watch directories (can be repeated). Overrides config file.
        #[arg(short, long)]
        watch: Vec<String>,
    },

    /// Verify SHA-256 integrity of the community rule pack.
    Verify,

    /// Download the latest community rule pack and verify it.
    Update,

    /// Manage runtime hooks for local AI agents (Tier 1).
    #[command(subcommand)]
    Hooks(HooksCmd),

    /// Inspect or wrap Model Context Protocol (MCP) servers (Tier 1).
    #[command(subcommand)]
    Mcp(McpCmd),

    /// Run a standalone OTLP ingest server (Tier 1).
    Otlp {
        /// Bind address (default 127.0.0.1:4318).
        #[arg(long, default_value = "127.0.0.1:4318")]
        bind: String,
    },
}

#[derive(Subcommand, Debug)]
enum HooksCmd {
    /// Install hooks for one or all supported AI runtimes.
    Install {
        /// Target: claude-code | cursor | codex | aider | all
        target: String,
        /// OTLP endpoint hooks should send to. Default http://127.0.0.1:4318
        #[arg(long, default_value = "http://127.0.0.1:4318")]
        endpoint: String,
    },
    /// Remove hooks previously installed by AgentDR.
    Uninstall {
        /// Target: claude-code | cursor | codex | aider | all
        target: String,
    },
    /// Print install status for all supported runtimes.
    Status,
}

#[derive(Subcommand, Debug)]
enum McpCmd {
    /// Discover and emit MCP server configuration across the host.
    Inventory {
        /// Emit one JSONL event line per discovered server to stdout.
        #[arg(long, default_value_t = false)]
        jsonl: bool,
    },
    /// stdio-proxy an MCP server: log every JSON-RPC message to AgentDR.
    ///
    /// Use as: adr-agent mcp wrap --name my-server -- <server-binary> [args...]
    Wrap {
        /// Logical server name to record in events.
        #[arg(long)]
        name: String,
        /// Command to execute (mandatory). Provide after `--`.
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("adr_agent=info,axum=info,tower_http=info")),
        )
        .with_target(false)
        .init();

    let config_path = cli.config.clone().unwrap_or_else(|| cli.root.join("config.toml"));

    match cli.command.unwrap_or(Command::Start { quiet: false, watch: Vec::new() }) {
        Command::Verify => {
            let ri = integrity::RuleIntegrity::discover();
            let status = ri.status();
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            if status.integrity != "ok" {
                std::process::exit(1);
            }
        }

        Command::Update => {
            let ri = integrity::RuleIntegrity::discover();
            let result = ri.update(true);
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            if result.status == "integrity_failed" || result.status == "error" {
                std::process::exit(1);
            }
        }

        Command::Hooks(HooksCmd::Install { target, endpoint }) => {
            if let Err(e) = hooks::install(&target, &endpoint) {
                eprintln!("install failed: {e}");
                std::process::exit(1);
            }
        }
        Command::Hooks(HooksCmd::Uninstall { target }) => {
            if let Err(e) = hooks::uninstall(&target) {
                eprintln!("uninstall failed: {e}");
                std::process::exit(1);
            }
        }
        Command::Hooks(HooksCmd::Status) => {
            let s = hooks::status();
            println!("{}", serde_json::to_string_pretty(&s).unwrap());
        }

        Command::Mcp(McpCmd::Inventory { jsonl }) => {
            let inv = mcp::inventory::scan();
            if jsonl {
                for ev in &inv.events {
                    println!("{}", serde_json::to_string(ev).unwrap());
                }
            } else {
                println!("{}", serde_json::to_string_pretty(&inv).unwrap());
            }
        }
        Command::Mcp(McpCmd::Wrap { name, cmd }) => {
            // Resolve event-log target inside <root>/<config.storage.events_path>.
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            match mcp::intercept::run(&name, &cmd, &log_path).await {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("mcp wrap failed: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Otlp { bind } => {
            let cfg = config::Config::load(&config_path);
            let log_path = cli.root.join(&cfg.storage.events_path);
            ingest::otlp::serve_standalone(&bind, &log_path).await;
        }

        Command::Start { quiet, watch } => {
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
            let mut cfg = config::Config::load(&config_path);

            // CLI overrides
            if !watch.is_empty() {
                cfg.watch_directories = watch;
            }

            tracing::info!(
                root = %cli.root.display(),
                watch_dirs = ?cfg.watch_directories,
                detection_rules = 20,
                otlp_enabled = cfg.otlp.enabled,
                mcp_inventory_on_start = cfg.mcp.inventory_on_start,
                "CoSAI ADR Agent v{} (Rust) — CoSAI OCSF Category 7",
                env!("CARGO_PKG_VERSION"),
            );

            let engine = engine::AgentEngine::new(cli.root, cfg, !quiet);
            engine.run().await;
        }
    }
}
