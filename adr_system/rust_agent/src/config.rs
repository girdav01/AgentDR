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

    #[serde(default)]
    pub exporters: ExportersConfig,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub proxy: ProxyConfig,

    #[serde(default)]
    pub kernel: KernelConfig,

    #[serde(default)]
    pub browser: BrowserConfig,
}

// ── Tier 5 policy + inline proxy ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Load and evaluate policies against each event.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional override path. When empty, the agent searches
    /// `<exe>/../cosai-community/policies/policies.yaml`, then
    /// `cosai-community/policies/policies.yaml`, then `/etc/agentdr/policies.yaml`.
    #[serde(default)]
    pub path: String,
}
impl Default for PolicyConfig {
    fn default() -> Self { Self { enabled: true, path: String::new() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Run the inline blocking HTTP CONNECT proxy.
    #[serde(default)]
    pub enabled: bool,
    /// Bind address, e.g. 127.0.0.1:8080.
    #[serde(default = "default_proxy_bind")]
    pub bind: String,
    /// Optional hostname allow-list (substring match, case-insensitive).
    /// When empty, only the PolicyEngine decides.
    #[serde(default)]
    pub allowlist: Vec<String>,
}
impl Default for ProxyConfig {
    fn default() -> Self {
        Self { enabled: false, bind: default_proxy_bind(), allowlist: Vec::new() }
    }
}
fn default_proxy_bind() -> String { "127.0.0.1:8080".into() }

// ── Tier 6 — kernel + browser telemetry ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    /// Subscribe to OS-native process / file telemetry. Linux uses the
    /// kernel audit netlink (no extra daemon required); macOS and
    /// Windows currently emit a stub event indicating signed-binary
    /// requirements for EndpointSecurity / ETW providers.
    #[serde(default)]
    pub enabled: bool,
    /// Linux only — netlink multicast group, default 1 (matches auditd).
    #[serde(default = "default_audit_group")]
    pub audit_multicast_group: u32,
}
impl Default for KernelConfig {
    fn default() -> Self { Self { enabled: false, audit_multicast_group: default_audit_group() } }
}
fn default_audit_group() -> u32 { 1 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserConfig {
    /// Poll Chrome / Edge DevTools Protocol for browser-use agent activity.
    #[serde(default)]
    pub enabled: bool,
    /// CDP endpoint; default Chrome/Edge "remote debugging" port.
    #[serde(default = "default_cdp_endpoint")]
    pub cdp_endpoint: String,
    /// Polling interval in seconds.
    #[serde(default = "default_cdp_poll")]
    pub poll_seconds: u64,
}
impl Default for BrowserConfig {
    fn default() -> Self { Self { enabled: false, cdp_endpoint: default_cdp_endpoint(), poll_seconds: default_cdp_poll() } }
}
fn default_cdp_endpoint() -> String { "http://127.0.0.1:9222".into() }
fn default_cdp_poll() -> u64 { 5 }

// ── Tier 3 exporters ────────────────────────────────────────────────────
//
// All exporters share a small `BatchConfig` and have a per-backend
// settings block. Each block has `enabled = false` by default; an
// operator enables only the destinations they actually use.

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExportersConfig {
    #[serde(default)] pub splunk:     SplunkConfig,
    #[serde(default)] pub datadog:    DatadogConfig,
    #[serde(default)] pub elastic:    ElasticConfig,
    #[serde(default)] pub chronicle:  ChronicleConfig,
    #[serde(default)] pub xsiam:      XsiamConfig,
    #[serde(default)] pub snowflake:  SnowflakeConfig,
    #[serde(default)] pub sentinel:   SentinelConfig,
    #[serde(default)] pub wazuh:      WazuhConfig,
    #[serde(default)] pub syslog:     SyslogConfig,
    #[serde(default)] pub ocsf:       OcsfConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchConfig {
    #[serde(default = "default_batch_size_50")]   pub batch_size: usize,
    #[serde(default = "default_flush_interval_5")] pub flush_interval_seconds: u64,
    #[serde(default = "default_timeout_10")]      pub timeout_seconds: u64,
    #[serde(default = "default_max_retries_3")]   pub max_retries: u32,
}
impl Default for BatchConfig {
    fn default() -> Self {
        Self { batch_size: 50, flush_interval_seconds: 5, timeout_seconds: 10, max_retries: 3 }
    }
}
fn default_batch_size_50() -> usize { 50 }
fn default_flush_interval_5() -> u64 { 5 }
fn default_timeout_10() -> u64 { 10 }
fn default_max_retries_3() -> u32 { 3 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SplunkConfig {
    #[serde(default)] pub enabled: bool,
    /// HEC endpoint, e.g. https://splunk.example.com:8088
    #[serde(default)] pub endpoint: String,
    /// HEC token
    #[serde(default)] pub token: String,
    /// Splunk index (optional — falls back to HEC default)
    #[serde(default)] pub index: String,
    /// HEC sourcetype (default `agentdr:aitf`)
    #[serde(default = "default_splunk_sourcetype")] pub sourcetype: String,
    /// Verify TLS certificate (default true)
    #[serde(default = "default_true")] pub verify_tls: bool,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_splunk_sourcetype() -> String { "agentdr:aitf".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DatadogConfig {
    #[serde(default)] pub enabled: bool,
    /// API key
    #[serde(default)] pub api_key: String,
    /// Datadog site, e.g. datadoghq.com | datadoghq.eu | us3.datadoghq.com
    #[serde(default = "default_dd_site")] pub site: String,
    /// `service` tag
    #[serde(default = "default_dd_service")] pub service: String,
    /// Static tag list (env:prod, team:secops, ...)
    #[serde(default)] pub tags: Vec<String>,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_dd_site() -> String { "datadoghq.com".into() }
fn default_dd_service() -> String { "agentdr".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ElasticConfig {
    #[serde(default)] pub enabled: bool,
    /// Cluster URL, e.g. https://elastic.example.com:9200
    #[serde(default)] pub endpoint: String,
    /// Index name (we append a yyyy.MM.dd suffix automatically)
    #[serde(default = "default_es_index")] pub index: String,
    /// API key (base64 id:key). Mutually exclusive with basic_auth.
    #[serde(default)] pub api_key: String,
    /// `user:password` for basic auth (if api_key is empty)
    #[serde(default)] pub basic_auth: String,
    /// Verify TLS certificate
    #[serde(default = "default_true")] pub verify_tls: bool,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_es_index() -> String { "agentdr-events".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChronicleConfig {
    #[serde(default)] pub enabled: bool,
    /// Customer GUID (Chronicle tenant)
    #[serde(default)] pub customer_id: String,
    /// Ingestion endpoint (region-specific, e.g.
    /// https://malachiteingestion-pa.googleapis.com)
    #[serde(default = "default_chronicle_endpoint")] pub endpoint: String,
    /// OAuth2 access token (operator-supplied; we don't sign JWTs here)
    #[serde(default)] pub access_token: String,
    /// Chronicle namespace
    #[serde(default = "default_chronicle_namespace")] pub namespace: String,
    /// Log type to apply (forwarded with each event)
    #[serde(default = "default_chronicle_log_type")] pub log_type: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_chronicle_endpoint() -> String { "https://malachiteingestion-pa.googleapis.com".into() }
fn default_chronicle_namespace() -> String { "agentdr".into() }
fn default_chronicle_log_type() -> String { "AGENTDR_AITF".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XsiamConfig {
    #[serde(default)] pub enabled: bool,
    /// HTTP Log Collector URL (Cortex XSIAM "Generic HTTPs Collector" address)
    #[serde(default)] pub endpoint: String,
    /// Auth token (XSIAM "API Key")
    #[serde(default)] pub auth_token: String,
    /// Static `vendor` / `product` tags
    #[serde(default = "default_xsiam_vendor")]  pub vendor:  String,
    #[serde(default = "default_xsiam_product")] pub product: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_xsiam_vendor()  -> String { "CoSAI".into() }
fn default_xsiam_product() -> String { "AgentDR".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SnowflakeConfig {
    #[serde(default)] pub enabled: bool,
    /// Snowpipe REST endpoint or Snowpipe Streaming insert URL
    #[serde(default)] pub endpoint: String,
    /// Bearer JWT (operator-supplied — generate with snowsql / Snowflake CLI)
    #[serde(default)] pub bearer_jwt: String,
    /// Optional pipe name (Snowpipe classic). Streaming users leave empty.
    #[serde(default)] pub pipe: String,
    #[serde(default)] pub batch: BatchConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)] pub enabled: bool,
    /// Log Analytics workspace ID (GUID)
    #[serde(default)] pub workspace_id: String,
    /// Shared key (primary or secondary) — base64
    #[serde(default)] pub shared_key: String,
    /// Custom log type (Sentinel appends "_CL")
    #[serde(default = "default_sentinel_log_type")] pub log_type: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_sentinel_log_type() -> String { "AgentDR_AITF".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WazuhConfig {
    #[serde(default)] pub enabled: bool,
    /// Output file path (must be readable by the wazuh-agent's logcollector,
    /// e.g. `/var/ossec/logs/agentdr.json`).
    #[serde(default = "default_wazuh_path")] pub output_path: String,
    /// Rotate after N bytes
    #[serde(default = "default_wazuh_rotate")] pub rotate_bytes: u64,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_wazuh_path() -> String { "/var/ossec/logs/agentdr.json".into() }
fn default_wazuh_rotate() -> u64 { 50 * 1024 * 1024 }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyslogConfig {
    #[serde(default)] pub enabled: bool,
    /// "udp" | "tcp"
    #[serde(default = "default_syslog_proto")] pub protocol: String,
    /// host:port (e.g. siem.example.com:514)
    #[serde(default = "default_syslog_addr")] pub address: String,
    /// RFC 5424 facility (1..23)
    #[serde(default = "default_syslog_facility")] pub facility: u8,
    /// RFC 5424 APP-NAME field
    #[serde(default = "default_syslog_appname")] pub appname: String,
    #[serde(default)] pub batch: BatchConfig,
}
fn default_syslog_proto() -> String { "udp".into() }
fn default_syslog_addr()  -> String { "127.0.0.1:514".into() }
fn default_syslog_facility() -> u8 { 13 } // log audit
fn default_syslog_appname() -> String { "agentdr".into() }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OcsfConfig {
    #[serde(default)] pub enabled: bool,
    /// HTTP endpoint accepting OCSF Category 7 JSON
    #[serde(default)] pub endpoint: String,
    /// Optional bearer token
    #[serde(default)] pub bearer_token: String,
    #[serde(default)] pub batch: BatchConfig,
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
            exporters: ExportersConfig::default(),
            policy: PolicyConfig::default(),
            proxy: ProxyConfig::default(),
            kernel: KernelConfig::default(),
            browser: BrowserConfig::default(),
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
