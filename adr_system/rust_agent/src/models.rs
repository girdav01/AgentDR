//! CoSAI OCSF Category 7 constants, EventRecord, agent signatures, detection rules.
//!
//! Detection signatures, AI-endpoint rules, and messaging-endpoint rules are
//! loaded at runtime from the `cosai-community/rules/` JSON files so they can
//! be updated **without recompiling** the agent binary.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;
use uuid::Uuid;

// ── CoSAI OCSF Category 7 Event Classes ──
pub const CLASS_LLM_INFERENCE: u32 = 7001;
pub const CLASS_AGENT_ACTION: u32 = 7002;
pub const CLASS_TOOL_EXECUTION: u32 = 7003;
pub const CLASS_MCP_OPERATION: u32 = 7004;
pub const CLASS_PROMPT_INJECTION: u32 = 7005;
pub const CLASS_DATA_EXFILTRATION: u32 = 7006;
pub const CLASS_PERMISSION_ESCALATION: u32 = 7007;
pub const CLASS_COMPLIANCE_VIOLATION: u32 = 7008;
pub const CLASS_GUARDRAIL_EVENT: u32 = 7009;
pub const CLASS_COST_ANOMALY: u32 = 7010;

// ── Activity IDs ──
pub const ACTIVITY_CREATE: u32 = 1;
pub const ACTIVITY_READ: u32 = 2;
pub const ACTIVITY_UPDATE: u32 = 3;
pub const ACTIVITY_DELETE: u32 = 4;
pub const ACTIVITY_EXECUTE: u32 = 5;
pub const ACTIVITY_DETECT: u32 = 6;
pub const ACTIVITY_BLOCK: u32 = 7;

// ── Status IDs ──
pub const STATUS_SUCCESS: u32 = 1;
pub const STATUS_FAILURE: u32 = 2;
pub const STATUS_BLOCKED: u32 = 3;

/// Map risk level string to OCSF severity_id.
pub fn severity_from_risk(risk: &str) -> u32 {
    match risk {
        "low" => 1,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 1,
    }
}

pub fn utc_now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn gen_trace_id() -> String {
    Uuid::new_v4().simple().to_string()[..32].to_string()
}

pub fn gen_span_id() -> String {
    Uuid::new_v4().simple().to_string()[..16].to_string()
}

// ══════════════════════════════════════════════════════════════════════
// JSON rule-file loader — reads cosai-community/rules/ at runtime so
// detection signatures can be updated without recompiling the binary.
// ══════════════════════════════════════════════════════════════════════

fn rules_dir() -> PathBuf {
    // Resolve: <exe_dir>/../cosai-community/rules/  (development layout)
    // Falls back to <cwd>/cosai-community/rules/ if the first doesn't exist.
    let exe = std::env::current_exe().unwrap_or_default();
    let dev = exe.parent().unwrap_or(std::path::Path::new("."))
        .join("../cosai-community/rules");
    if dev.exists() { return dev; }
    PathBuf::from("cosai-community/rules")
}

fn load_json(filename: &str) -> serde_json::Value {
    let path = rules_dir().join(filename);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
        Err(_) => {
            eprintln!("[cosai] warning: could not load {:?}", path);
            serde_json::Value::Null
        }
    }
}

// ── Agent Categories ──

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentCategory {
    Coding, General, Workflow, Enterprise, Browser, Unknown,
}

impl AgentCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Coding     => "coding",
            Self::General    => "general",
            Self::Workflow   => "workflow",
            Self::Enterprise => "enterprise",
            Self::Browser    => "browser",
            Self::Unknown    => "unknown",
        }
    }
    fn from_str(s: &str) -> Self {
        match s {
            "coding"     => Self::Coding,
            "general"    => Self::General,
            "workflow"   => Self::Workflow,
            "enterprise" => Self::Enterprise,
            "browser"    => Self::Browser,
            _            => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AgentSignature {
    pub name: String,
    pub framework: String,
    pub category: AgentCategory,
}

/// Flattened (pattern → signature) pairs loaded from agent-signatures.json.
struct LoadedSignatures {
    entries: Vec<(String, AgentSignature)>,
}

fn loaded_signatures() -> &'static LoadedSignatures {
    static INSTANCE: OnceLock<LoadedSignatures> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let val = load_json("agent-signatures.json");
        let mut entries = Vec::new();
        if let Some(sigs) = val.get("signatures").and_then(|v| v.as_array()) {
            for sig in sigs {
                let name = sig.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let framework = sig.get("framework").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let cat = AgentCategory::from_str(
                    sig.get("category").and_then(|v| v.as_str()).unwrap_or("unknown")
                );
                if let Some(pats) = sig.get("process_patterns").and_then(|v| v.as_array()) {
                    for pat in pats {
                        if let Some(p) = pat.as_str() {
                            entries.push((p.to_string(), AgentSignature {
                                name: name.clone(), framework: framework.clone(), category: cat.clone(),
                            }));
                        }
                    }
                }
            }
        }
        LoadedSignatures { entries }
    })
}

/// Identify an AI agent from process details (name + exe + cmdline concatenated).
pub fn identify_agent(haystack: &str) -> Option<AgentSignature> {
    let lower = haystack.to_lowercase();
    for (key, sig) in &loaded_signatures().entries {
        if lower.contains(key.as_str()) {
            return Some(sig.clone());
        }
    }
    None
}

// ── AI provider classification (loaded from ai-endpoints.json) ──

#[derive(Debug, Clone, Serialize)]
pub struct AiProviderInfo {
    pub provider: String,
    pub model: String,
}

#[derive(Debug)]
struct AiEndpointRule {
    patterns: Vec<String>,
    requires_also: Option<String>,
    provider: String,
    model: String,
}

struct LoadedAiEndpoints {
    rules: Vec<AiEndpointRule>,
}

fn loaded_ai_endpoints() -> &'static LoadedAiEndpoints {
    static INSTANCE: OnceLock<LoadedAiEndpoints> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let val = load_json("ai-endpoints.json");
        let mut rules = Vec::new();
        if let Some(eps) = val.get("endpoints").and_then(|v| v.as_array()) {
            for ep in eps {
                let patterns: Vec<String> = ep.get("patterns")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|p| p.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                let requires_also = ep.get("requires_also").and_then(|v| v.as_str()).map(String::from);
                let provider = ep.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let model = ep.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string();
                rules.push(AiEndpointRule { patterns, requires_also, provider, model });
            }
        }
        LoadedAiEndpoints { rules }
    })
}

pub fn classify_ai_endpoint(host: &str) -> Option<AiProviderInfo> {
    let h = host.to_lowercase();
    if h.is_empty() { return None; }
    for rule in &loaded_ai_endpoints().rules {
        if let Some(ref also) = rule.requires_also {
            if !h.contains(also.as_str()) { continue; }
        }
        for pat in &rule.patterns {
            if h.contains(pat.as_str()) {
                return Some(AiProviderInfo {
                    provider: rule.provider.clone(),
                    model: rule.model.clone(),
                });
            }
        }
    }
    None
}

// ── Messaging platform classification (loaded from messaging-endpoints.json) ──

struct LoadedMessagingEndpoints {
    entries: Vec<(String, String)>,
}

fn loaded_messaging_endpoints() -> &'static LoadedMessagingEndpoints {
    static INSTANCE: OnceLock<LoadedMessagingEndpoints> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let val = load_json("messaging-endpoints.json");
        let mut entries = Vec::new();
        if let Some(eps) = val.get("endpoints").and_then(|v| v.as_array()) {
            for ep in eps {
                let pat = ep.get("pattern").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let plat = ep.get("platform").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if !pat.is_empty() { entries.push((pat, plat)); }
            }
        }
        LoadedMessagingEndpoints { entries }
    })
}

pub fn classify_messaging_endpoint(host: &str) -> Option<String> {
    let h = host.to_lowercase();
    for (endpoint, platform) in &loaded_messaging_endpoints().entries {
        if h.contains(endpoint.as_str()) {
            return Some(platform.clone());
        }
    }
    None
}

// ── Skill path detection ──

static SKILL_PATHS: &[&str] = &[
    ".openclaw/skills",
    "openclaw_skills",
    "skills/",
    ".autogpt/plugins",
    "plugins/",
    ".agent/tools",
];

pub fn is_skill_path(filepath: &str) -> bool {
    let lower = filepath.to_lowercase().replace('\\', "/");
    SKILL_PATHS.iter().any(|sp| lower.contains(sp))
}

// ── Detection rules ──

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub name: &'static str,
    pub owasp: &'static str,
    pub class_uid: u32,
}

pub fn detection_rules() -> HashMap<&'static str, DetectionRule> {
    let mut m = HashMap::new();
    m.insert("AITF-DET-001", DetectionRule { name: "Prompt Injection Detected", owasp: "LLM01", class_uid: 7005 });
    m.insert("AITF-DET-002", DetectionRule { name: "Sensitive Data in Output", owasp: "LLM02", class_uid: 7006 });
    m.insert("AITF-DET-003", DetectionRule { name: "Excessive Token Usage", owasp: "LLM04", class_uid: 7010 });
    m.insert("AITF-DET-004", DetectionRule { name: "Unauthorized Tool Execution", owasp: "LLM05", class_uid: 7003 });
    m.insert("AITF-DET-005", DetectionRule { name: "Excessive Agency / Autonomy", owasp: "LLM08", class_uid: 7002 });
    m.insert("AITF-DET-006", DetectionRule { name: "Supply Chain Anomaly", owasp: "LLM03", class_uid: 7004 });
    m.insert("AITF-DET-007", DetectionRule { name: "Insecure Output Handling", owasp: "LLM02", class_uid: 7009 });
    m.insert("AITF-DET-008", DetectionRule { name: "Model Denial of Service", owasp: "LLM04", class_uid: 7010 });
    m.insert("AITF-DET-009", DetectionRule { name: "Rapid File Modifications", owasp: "LLM08", class_uid: 7002 });
    m.insert("AITF-DET-010", DetectionRule { name: "Bulk Data Deletion", owasp: "LLM06", class_uid: 7006 });
    m.insert("AITF-DET-011", DetectionRule { name: "Permission Boundary Violation", owasp: "LLM05", class_uid: 7007 });
    m.insert("AITF-DET-012", DetectionRule { name: "Unusual API Volume", owasp: "LLM04", class_uid: 7010 });
    m.insert("AITF-DET-013", DetectionRule { name: "MCP Server Abuse", owasp: "LLM05", class_uid: 7004 });
    m.insert("AITF-DET-014", DetectionRule { name: "Compliance Drift", owasp: "LLM09", class_uid: 7008 });
    m.insert("AITF-DET-015", DetectionRule { name: "Malicious Skill/Plugin Loaded", owasp: "LLM03", class_uid: 7004 });
    m.insert("AITF-DET-016", DetectionRule { name: "Unauthorized Messaging Channel Access", owasp: "LLM05", class_uid: 7007 });
    m.insert("AITF-DET-017", DetectionRule { name: "Shell Command Execution by Agent", owasp: "LLM08", class_uid: 7003 });
    m.insert("AITF-DET-018", DetectionRule { name: "Agent Credential / Secret Access", owasp: "LLM06", class_uid: 7006 });
    m.insert("AITF-DET-019", DetectionRule { name: "Cross-Platform Data Relay", owasp: "LLM02", class_uid: 7006 });
    m.insert("AITF-DET-020", DetectionRule { name: "Unvetted Skill Installation", owasp: "LLM03", class_uid: 7004 });
    m
}

// ── Credential file patterns ──

pub static CREDENTIAL_PATTERNS: &[&str] = &[
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "authorized_keys",
    ".aws/credentials", ".aws/config",
    ".gcloud/credentials.json", ".config/gcloud",
    ".npmrc", ".pypirc",
    "secrets.json", "service-account.json", "keyfile.json",
];

pub fn is_credential_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    CREDENTIAL_PATTERNS.iter().any(|p| lower.contains(&p.to_lowercase()))
}

// ── The core event record ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub timestamp: String,
    pub event_type: String,
    pub details: serde_json::Value,
    pub risk_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_detected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    // CoSAI OCSF Category 7 fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_framework: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compliance: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_finding: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_usage: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_info: Option<serde_json::Value>,
    pub trace_id: String,
    pub span_id: String,
}

impl EventRecord {
    pub fn new(event_type: &str, details: serde_json::Value, risk_level: &str) -> Self {
        let severity_id = severity_from_risk(risk_level);
        Self {
            timestamp: utc_now_iso(),
            event_type: event_type.to_string(),
            details,
            risk_level: risk_level.to_string(),
            agent_detected: None,
            source: None,
            class_uid: None,
            type_uid: None,
            activity_id: None,
            severity_id: Some(severity_id),
            status_id: Some(STATUS_SUCCESS),
            message: None,
            provider: None,
            model: None,
            agent_name: None,
            agent_framework: None,
            tool_name: None,
            mcp_server: None,
            actor: None,
            compliance: None,
            security_finding: None,
            token_usage: None,
            cost_info: None,
            trace_id: gen_trace_id(),
            span_id: gen_span_id(),
        }
    }
}
