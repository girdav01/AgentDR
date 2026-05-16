//! Configuration loading and defaults.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_watch_dirs")]
    pub watch_directories: Vec<String>,

    #[serde(default)]
    pub file_monitor: FileMonitorConfig,

    #[serde(default)]
    pub network_monitor: NetworkMonitorConfig,

    #[serde(default)]
    pub process_monitor: ProcessMonitorConfig,

    #[serde(default)]
    pub detection: DetectionConfig,

    #[serde(default)]
    pub storage: StorageConfig,

    #[serde(default)]
    pub server_push: ServerPushConfig,

    #[serde(default)]
    pub runtime: RuntimeConfig,

    #[serde(default)]
    pub otlp: OtlpConfig,

    #[serde(default)]
    pub mcp: McpConfig,
}

// ── OTLP ingest (Tier 1) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_otlp_bind")]
    pub bind: String,
    /// Maximum accepted request body size (bytes). Default 4 MiB.
    #[serde(default = "default_otlp_max_bytes")]
    pub max_body_bytes: usize,
    /// When true, OTLP log records and span attributes that look like
    /// prompts/messages are dropped before storage.
    #[serde(default = "default_true")]
    pub redact_content: bool,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_otlp_bind(),
            max_body_bytes: default_otlp_max_bytes(),
            redact_content: true,
        }
    }
}

fn default_otlp_bind() -> String { "127.0.0.1:4318".into() }
fn default_otlp_max_bytes() -> usize { 4 * 1024 * 1024 }

// ── MCP (Tier 1) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Scan known MCP config locations at startup and emit class_uid=7004 events.
    #[serde(default = "default_true")]
    pub inventory_on_start: bool,
    /// Periodically re-scan every N seconds (0 = disabled).
    #[serde(default = "default_mcp_rescan")]
    pub rescan_seconds: u64,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            inventory_on_start: true,
            rescan_seconds: default_mcp_rescan(),
        }
    }
}

fn default_mcp_rescan() -> u64 { 600 }

fn default_watch_dirs() -> Vec<String> {
    Vec::new()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMonitorConfig {
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default = "default_ignore_patterns")]
    pub ignore_patterns: Vec<String>,
}

impl Default for FileMonitorConfig {
    fn default() -> Self {
        Self {
            recursive: true,
            ignore_patterns: default_ignore_patterns(),
        }
    }
}

fn default_true() -> bool { true }

fn default_ignore_patterns() -> Vec<String> {
    vec!["*.tmp".into(), "*.swp".into(), "*.DS_Store".into(), "*.jsonl".into(), "*.log".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitorConfig {
    #[serde(default = "default_poll_seconds")]
    pub poll_seconds: u64,
    #[serde(default = "default_ai_endpoints")]
    pub ai_api_endpoints: Vec<String>,
}

impl Default for NetworkMonitorConfig {
    fn default() -> Self {
        Self {
            poll_seconds: 3,
            ai_api_endpoints: default_ai_endpoints(),
        }
    }
}

fn default_poll_seconds() -> u64 { 3 }

fn default_ai_endpoints() -> Vec<String> {
    vec![
        "api.openai.com".into(),
        "api.anthropic.com".into(),
        "generativelanguage.googleapis.com".into(),
        "api.mistral.ai".into(),
        "api.deepseek.com".into(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorConfig {
    #[serde(default = "default_process_poll")]
    pub poll_interval_seconds: u64,
}

impl Default for ProcessMonitorConfig {
    fn default() -> Self {
        Self { poll_interval_seconds: 2 }
    }
}

fn default_process_poll() -> u64 { 2 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    #[serde(default)]
    pub rapid_file_modifications: ThresholdRule,
    #[serde(default)]
    pub unusual_api_call_volume: ThresholdRule,
    #[serde(default)]
    pub large_file_deletions: LargeDeletionRule,
    #[serde(default)]
    pub malicious_skill_plugin: ThresholdRule,
    #[serde(default)]
    pub unauthorized_messaging: EnabledRule,
    #[serde(default)]
    pub shell_command_execution: ThresholdRule,
    #[serde(default)]
    pub credential_access: EnabledRule,
    #[serde(default)]
    pub cross_platform_relay: WindowRule,
    #[serde(default)]
    pub unvetted_skill_install: EnabledRule,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            rapid_file_modifications: ThresholdRule { enabled: true, threshold_count: 10, window_seconds: 60 },
            unusual_api_call_volume: ThresholdRule { enabled: true, threshold_count: 40, window_seconds: 60 },
            large_file_deletions: LargeDeletionRule::default(),
            malicious_skill_plugin: ThresholdRule { enabled: true, threshold_count: 5, window_seconds: 300 },
            unauthorized_messaging: EnabledRule { enabled: true },
            shell_command_execution: ThresholdRule { enabled: true, threshold_count: 5, window_seconds: 60 },
            credential_access: EnabledRule { enabled: true },
            cross_platform_relay: WindowRule { enabled: true, window_seconds: 300 },
            unvetted_skill_install: EnabledRule { enabled: true },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdRule {
    pub enabled: bool,
    pub threshold_count: usize,
    pub window_seconds: u64,
}

impl Default for ThresholdRule {
    fn default() -> Self {
        Self { enabled: true, threshold_count: 10, window_seconds: 60 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnabledRule {
    pub enabled: bool,
}

impl Default for EnabledRule {
    fn default() -> Self { Self { enabled: true } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowRule {
    pub enabled: bool,
    pub window_seconds: u64,
}

impl Default for WindowRule {
    fn default() -> Self { Self { enabled: true, window_seconds: 300 } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeDeletionRule {
    pub enabled: bool,
    pub single_file_mb: f64,
    pub window_total_mb: f64,
    pub window_seconds: u64,
}

impl Default for LargeDeletionRule {
    fn default() -> Self {
        Self {
            enabled: true,
            single_file_mb: 25.0,
            window_total_mb: 200.0,
            window_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_events_path")]
    pub events_path: String,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
    #[serde(default = "default_backup_count")]
    pub backup_count: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            events_path: default_events_path(),
            max_bytes: 5_000_000,
            backup_count: 7,
        }
    }
}

fn default_events_path() -> String { "logs/events.jsonl".into() }
fn default_max_bytes() -> u64 { 5_000_000 }
fn default_backup_count() -> u32 { 7 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPushConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_flush_interval")]
    pub flush_interval_seconds: u64,
}

impl Default for ServerPushConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: String::new(),
            api_key: String::new(),
            timeout_seconds: 5,
            batch_size: 10,
            flush_interval_seconds: 5,
        }
    }
}

fn default_timeout() -> u64 { 5 }
fn default_batch_size() -> usize { 10 }
fn default_flush_interval() -> u64 { 5 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    #[serde(default = "default_status_file")]
    pub status_file: String,
    #[serde(default = "default_log_file")]
    pub log_file: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            status_file: default_status_file(),
            log_file: default_log_file(),
        }
    }
}

fn default_status_file() -> String { "runtime/status.json".into() }
fn default_log_file() -> String { "logs/agent_runtime.log".into() }

impl Default for Config {
    fn default() -> Self {
        Self {
            watch_directories: Vec::new(),
            file_monitor: FileMonitorConfig::default(),
            network_monitor: NetworkMonitorConfig::default(),
            process_monitor: ProcessMonitorConfig::default(),
            detection: DetectionConfig::default(),
            storage: StorageConfig::default(),
            server_push: ServerPushConfig::default(),
            runtime: RuntimeConfig::default(),
            otlp: OtlpConfig::default(),
            mcp: McpConfig::default(),
        }
    }
}

impl Config {
    /// Load config from a TOML file, falling back to defaults.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
            Err(_) => {
                let cfg = Config::default();
                // Write default config for reference
                if let Ok(s) = toml::to_string_pretty(&cfg) {
                    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
                    let _ = std::fs::write(path, s);
                }
                cfg
            }
        }
    }
}
