//! Agent Engine — orchestrates monitors, detectors, and storage.

use crate::config::Config;
use crate::detectors::PatternDetector;
use crate::ingest::otlp::{self, OtlpSink};
use crate::mcp;
use crate::models::*;
use crate::monitors::{file::FileMonitor, network::NetworkMonitor, process::ProcessMonitor};
use crate::storage::{EventPusher, JsonlStore};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::time::{interval, Duration};
use tracing::info;

pub struct AgentEngine {
    config: Config,
    root_path: PathBuf,
    stream_output: bool,
}

impl AgentEngine {
    pub fn new(root_path: PathBuf, config: Config, stream_output: bool) -> Self {
        Self { config, root_path, stream_output }
    }

    pub async fn run(self) {
        info!("Starting CoSAI ADR Agent Engine (Rust)");

        // Shutdown signal
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Event channel — all monitors write here
        let (event_tx, mut event_rx) = mpsc::unbounded_channel::<EventRecord>();

        // Pusher channel (separate so we can clone events to it)
        let (push_tx, push_rx) = mpsc::unbounded_channel::<EventRecord>();

        // Storage
        let store_path = self.root_path.join(&self.config.storage.events_path);
        let store = Arc::new(JsonlStore::new(
            store_path,
            self.config.storage.max_bytes,
            self.config.storage.backup_count,
        ));

        // Status file
        self.write_status("running");

        // Spawn event pusher
        let pusher = EventPusher::new(&self.config.server_push);
        let pusher_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            pusher.run(push_rx, pusher_shutdown).await;
        });

        // Spawn process monitor
        let proc_tx = event_tx.clone();
        let proc_shutdown = shutdown_rx.clone();
        let proc_poll = self.config.process_monitor.poll_interval_seconds;
        tokio::spawn(async move {
            ProcessMonitor::new(proc_poll, proc_tx).run(proc_shutdown).await;
        });

        // Spawn file monitor
        let file_tx = event_tx.clone();
        let file_shutdown = shutdown_rx.clone();
        let watch_dirs = self.config.watch_directories.clone();
        let recursive = self.config.file_monitor.recursive;
        let ignore = self.config.file_monitor.ignore_patterns.clone();
        tokio::spawn(async move {
            FileMonitor::new(watch_dirs, recursive, ignore, file_tx)
                .run(file_shutdown).await;
        });

        // Spawn network monitor
        let net_tx = event_tx.clone();
        let net_shutdown = shutdown_rx.clone();
        let net_poll = self.config.network_monitor.poll_seconds;
        let ai_eps = self.config.network_monitor.ai_api_endpoints.clone();
        tokio::spawn(async move {
            NetworkMonitor::new(net_poll, ai_eps, net_tx).run(net_shutdown).await;
        });

        // ── Tier 1: OTLP ingest server ──
        if self.config.otlp.enabled {
            let otlp_tx = event_tx.clone();
            let otlp_shutdown = shutdown_rx.clone();
            let bind = self.config.otlp.bind.clone();
            let max = self.config.otlp.max_body_bytes;
            let redact = self.config.otlp.redact_content;
            tokio::spawn(async move {
                let sink = OtlpSink::new(otlp_tx, redact);
                otlp::serve(&bind, max, sink, otlp_shutdown).await;
            });
        }

        // ── Tier 1: MCP inventory (one-shot + optional periodic re-scan) ──
        if self.config.mcp.inventory_on_start {
            let mcp_tx = event_tx.clone();
            tokio::spawn(async move {
                let report = mcp::inventory::scan();
                for ev in report.events {
                    let _ = mcp_tx.send(ev);
                }
            });
        }
        if self.config.mcp.rescan_seconds > 0 {
            let mcp_tx = event_tx.clone();
            let mut mcp_shutdown = shutdown_rx.clone();
            let period = self.config.mcp.rescan_seconds;
            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(period));
                ticker.tick().await; // skip immediate tick (covered by inventory_on_start)
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            let report = mcp::inventory::scan();
                            for ev in report.events { let _ = mcp_tx.send(ev); }
                        }
                        _ = mcp_shutdown.changed() => { break; }
                    }
                }
            });
        }

        // Emit start event
        let start_event = {
            let mut ev = EventRecord::new("agent_started", json!({
                "watch_directories": self.config.watch_directories,
                "runtime": "rust",
                "version": env!("CARGO_PKG_VERSION"),
            }), "low");
            ev.source = Some("engine".into());
            ev.class_uid = Some(CLASS_AGENT_ACTION);
            ev.type_uid = Some(CLASS_AGENT_ACTION * 100 + ACTIVITY_CREATE);
            ev.activity_id = Some(ACTIVITY_CREATE);
            ev.status_id = Some(STATUS_SUCCESS);
            ev.message = Some("CoSAI ADR Agent Engine started (Rust)".into());
            ev.agent_name = Some("ADR Monitor".into());
            ev.agent_framework = Some("CoSAI".into());
            ev
        };
        let _ = event_tx.send(start_event);

        // Detector
        let mut detector = PatternDetector::new(self.config.detection.clone());

        // Ctrl+C handler
        let ctrl_c_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("Received Ctrl+C, shutting down...");
            let _ = ctrl_c_tx.send(true);
        });

        // Main event loop
        let stream = self.stream_output;
        let mut main_shutdown = shutdown_rx.clone();
        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    // Persist
                    store.write_event(&event);
                    let _ = push_tx.send(event.clone());

                    if stream {
                        Self::print_event(&event);
                    }

                    // Run detections
                    let alerts = detector.analyze(&event);
                    for alert in alerts {
                        store.write_event(&alert);
                        let _ = push_tx.send(alert.clone());
                        if stream {
                            Self::print_event(&alert);
                        }
                    }
                }
                _ = main_shutdown.changed() => {
                    break;
                }
            }
        }

        // Emit stop event
        let stop_event = {
            let mut ev = EventRecord::new("agent_stopped", json!({}), "low");
            ev.source = Some("engine".into());
            ev.class_uid = Some(CLASS_AGENT_ACTION);
            ev.type_uid = Some(CLASS_AGENT_ACTION * 100 + ACTIVITY_DELETE);
            ev.activity_id = Some(ACTIVITY_DELETE);
            ev.status_id = Some(STATUS_SUCCESS);
            ev.message = Some("CoSAI ADR Agent Engine stopped".into());
            ev
        };
        store.write_event(&stop_event);

        self.write_status("stopped");
        info!("CoSAI ADR Agent Engine shut down cleanly");
    }

    fn print_event(event: &EventRecord) {
        println!(
            "[{}] {:8} {:32} | {}",
            event.timestamp,
            event.risk_level.to_uppercase(),
            event.event_type,
            serde_json::to_string(&event.details).unwrap_or_default(),
        );
    }

    fn write_status(&self, status: &str) {
        let path = self.root_path.join(&self.config.runtime.status_file);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let payload = json!({
            "status": status,
            "timestamp": utc_now_iso(),
            "pid": std::process::id(),
            "runtime": "rust",
        });
        let _ = std::fs::write(path, serde_json::to_string_pretty(&payload).unwrap_or_default());
    }
}
