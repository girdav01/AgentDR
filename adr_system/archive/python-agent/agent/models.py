from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


RISK_LEVELS = {"low", "medium", "high", "critical"}

# ── Load CoSAI Community rule files ──
# Rules are stored in JSON so they can be updated without modifying code.
_RULES_DIR = Path(__file__).resolve().parent.parent / "cosai-community" / "rules"
_POLICIES_DIR = Path(__file__).resolve().parent.parent / "cosai-community" / "policies"


def _load_json(filepath: Path) -> dict:
    """Load a JSON file, returning empty dict on failure."""
    try:
        return json.loads(filepath.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        import warnings
        warnings.warn(f"CoSAI rules: could not load {filepath}: {exc}")
        return {}


_SIGNATURES_DATA = _load_json(_RULES_DIR / "agent-signatures.json")
_AI_ENDPOINTS_DATA = _load_json(_RULES_DIR / "ai-endpoints.json")
_MESSAGING_DATA = _load_json(_RULES_DIR / "messaging-endpoints.json")

# ---------- CoSAI OCSF Category 7 Event Classes ----------
# From https://github.com/girdav01/aitf spec
CLASS_LLM_INFERENCE = 7001
CLASS_AGENT_ACTION = 7002
CLASS_TOOL_EXECUTION = 7003
CLASS_MCP_OPERATION = 7004
CLASS_PROMPT_INJECTION = 7005
CLASS_DATA_EXFILTRATION = 7006
CLASS_PERMISSION_ESCALATION = 7007
CLASS_COMPLIANCE_VIOLATION = 7008
CLASS_GUARDRAIL_EVENT = 7009
CLASS_COST_ANOMALY = 7010

CLASS_LABELS = {
    7001: "LLM Inference",
    7002: "Agent Action",
    7003: "Tool Execution",
    7004: "MCP Operation",
    7005: "Prompt Injection",
    7006: "Data Exfiltration",
    7007: "Permission Escalation",
    7008: "Compliance Violation",
    7009: "Guardrail Event",
    7010: "Cost Anomaly",
}

# CoSAI Activity IDs
ACTIVITY_CREATE = 1
ACTIVITY_READ = 2
ACTIVITY_UPDATE = 3
ACTIVITY_DELETE = 4
ACTIVITY_EXECUTE = 5
ACTIVITY_DETECT = 6
ACTIVITY_BLOCK = 7

# Status IDs
STATUS_SUCCESS = 1
STATUS_FAILURE = 2
STATUS_BLOCKED = 3
STATUS_UNKNOWN = 0

# Severity mapping from risk_level
SEVERITY_MAP = {
    "low": 1,       # Informational
    "medium": 3,    # Medium
    "high": 4,      # High
    "critical": 5,  # Critical
}

# Known AI providers and models
AI_PROVIDERS = {
    "openai": {"name": "OpenAI", "models": ["gpt-4", "gpt-4o", "gpt-3.5-turbo", "o1", "o3"]},
    "anthropic": {"name": "Anthropic", "models": ["claude-3.5-sonnet", "claude-3-opus", "claude-4"]},
    "google": {"name": "Google", "models": ["gemini-pro", "gemini-2.0-flash"]},
    "deepseek": {"name": "DeepSeek", "models": ["deepseek-v3", "deepseek-r1"]},
    "mistral": {"name": "Mistral", "models": ["mistral-large-latest"]},
    "meta": {"name": "Meta", "models": ["llama-3.1-70b", "llama-4"]},
    "ollama": {"name": "Ollama (local)", "models": ["local-model"]},
    "microsoft": {"name": "Microsoft Copilot", "models": ["gpt-4-m365", "bing-copilot", "copilot-studio"]},
}

# Agent categories (derived from community rules, with fallback constants)
AGENT_CATEGORY_CODING = "coding"
AGENT_CATEGORY_GENERAL = "general"
AGENT_CATEGORY_WORKFLOW = "workflow"
AGENT_CATEGORY_ENTERPRISE = "enterprise"
AGENT_CATEGORY_BROWSER = "browser"

# ── Agent signatures — built from cosai-community/rules/agent-signatures.json ──
# Each process_pattern key maps to {"name", "framework", "category"}.
AGENT_SIGNATURES: Dict[str, Dict[str, str]] = {}
for _sig in _SIGNATURES_DATA.get("signatures", []):
    for _pat in _sig.get("process_patterns", []):
        AGENT_SIGNATURES[_pat] = {
            "name": _sig["name"],
            "framework": _sig["framework"],
            "category": _sig["category"],
        }

# ── Messaging endpoints — built from cosai-community/rules/messaging-endpoints.json ──
MESSAGING_ENDPOINTS: Dict[str, str] = {
    ep["pattern"]: ep["platform"]
    for ep in _MESSAGING_DATA.get("endpoints", [])
}

# Directories/paths where agent skills/plugins are typically stored
AGENT_SKILL_PATHS = [
    ".openclaw/skills",
    "openclaw_skills",
    "skills/",
    ".autogpt/plugins",
    "plugins/",
    ".agent/tools",
]

# CoSAI Detection Rules — expanded for general-purpose agents
DETECTION_RULES = {
    # ── Original CoSAI rules ──
    "AITF-DET-001": {"name": "Prompt Injection Detected", "owasp": "LLM01", "class_uid": 7005},
    "AITF-DET-002": {"name": "Sensitive Data in Output", "owasp": "LLM02", "class_uid": 7006},
    "AITF-DET-003": {"name": "Excessive Token Usage", "owasp": "LLM04", "class_uid": 7010},
    "AITF-DET-004": {"name": "Unauthorized Tool Execution", "owasp": "LLM05", "class_uid": 7003},
    "AITF-DET-005": {"name": "Excessive Agency / Autonomy", "owasp": "LLM08", "class_uid": 7002},
    "AITF-DET-006": {"name": "Supply Chain Anomaly", "owasp": "LLM03", "class_uid": 7004},
    "AITF-DET-007": {"name": "Insecure Output Handling", "owasp": "LLM02", "class_uid": 7009},
    "AITF-DET-008": {"name": "Model Denial of Service", "owasp": "LLM04", "class_uid": 7010},
    "AITF-DET-009": {"name": "Rapid File Modifications", "owasp": "LLM08", "class_uid": 7002},
    "AITF-DET-010": {"name": "Bulk Data Deletion", "owasp": "LLM06", "class_uid": 7006},
    "AITF-DET-011": {"name": "Permission Boundary Violation", "owasp": "LLM05", "class_uid": 7007},
    "AITF-DET-012": {"name": "Unusual API Volume", "owasp": "LLM04", "class_uid": 7010},
    "AITF-DET-013": {"name": "MCP Server Abuse", "owasp": "LLM05", "class_uid": 7004},
    "AITF-DET-014": {"name": "Compliance Drift", "owasp": "LLM09", "class_uid": 7008},
    # ── General-purpose agent rules ──
    "AITF-DET-015": {"name": "Malicious Skill/Plugin Loaded", "owasp": "LLM03", "class_uid": 7004},
    "AITF-DET-016": {"name": "Unauthorized Messaging Channel Access", "owasp": "LLM05", "class_uid": 7007},
    "AITF-DET-017": {"name": "Shell Command Execution by Agent", "owasp": "LLM08", "class_uid": 7003},
    "AITF-DET-018": {"name": "Agent Credential / Secret Access", "owasp": "LLM06", "class_uid": 7006},
    "AITF-DET-019": {"name": "Cross-Platform Data Relay", "owasp": "LLM02", "class_uid": 7006},
    "AITF-DET-020": {"name": "Unvetted Skill Installation", "owasp": "LLM03", "class_uid": 7004},
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def gen_trace_id() -> str:
    return uuid.uuid4().hex[:32]


def gen_span_id() -> str:
    return uuid.uuid4().hex[:16]


@dataclass
class EventRecord:
    """CoSAI OCSF-compliant event record.

    Extends the base event with OCSF Category 7 fields:
    class_uid, type_uid, activity_id, severity_id, status_id,
    provider, model, agent_name, agent_framework, tool_name,
    mcp_server, actor, compliance, security_finding, token_usage,
    cost_info, trace_id, span_id.
    """
    timestamp: str
    event_type: str
    details: Dict[str, Any]
    risk_level: str = "low"
    agent_detected: Optional[str] = None
    source: Optional[str] = None
    tags: Dict[str, Any] = field(default_factory=dict)

    # CoSAI OCSF Category 7 fields
    class_uid: Optional[int] = None
    type_uid: Optional[int] = None
    activity_id: Optional[int] = None
    severity_id: Optional[int] = None
    status_id: Optional[int] = None
    message: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    agent_name: Optional[str] = None
    agent_framework: Optional[str] = None
    tool_name: Optional[str] = None
    mcp_server: Optional[str] = None
    actor: Optional[Dict[str, Any]] = None
    compliance: Optional[Dict[str, Any]] = None
    security_finding: Optional[Dict[str, Any]] = None
    token_usage: Optional[Dict[str, Any]] = None
    cost_info: Optional[Dict[str, Any]] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.risk_level not in RISK_LEVELS:
            self.risk_level = "low"
        if not self.timestamp:
            self.timestamp = utc_now_iso()
        # Auto-set severity from risk_level if not provided
        if self.severity_id is None:
            self.severity_id = SEVERITY_MAP.get(self.risk_level, 1)
        # Auto-set status if not provided
        if self.status_id is None:
            self.status_id = STATUS_SUCCESS
        # Generate trace/span IDs if not provided
        if self.trace_id is None:
            self.trace_id = gen_trace_id()
        if self.span_id is None:
            self.span_id = gen_span_id()

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        # Remove None values for cleaner JSONL output
        return {k: v for k, v in payload.items() if v is not None}


def classify_ai_endpoint(host: str) -> Optional[Dict[str, str]]:
    """Identify AI provider/model from API endpoint hostname.

    Rules are loaded from cosai-community/rules/ai-endpoints.json so new
    providers can be added by editing the JSON without touching this code.
    """
    host_lower = host.lower() if host else ""
    if not host_lower:
        return None
    for ep in _AI_ENDPOINTS_DATA.get("endpoints", []):
        patterns = ep.get("patterns", [])
        requires_also = ep.get("requires_also")
        if requires_also and requires_also not in host_lower:
            continue
        for pat in patterns:
            if pat in host_lower:
                return {"provider": ep["provider"], "model": ep["model"]}
    return None


def classify_messaging_endpoint(host: str) -> Optional[str]:
    """Identify messaging platform from API endpoint hostname."""
    host_lower = host.lower() if host else ""
    for endpoint, platform in MESSAGING_ENDPOINTS.items():
        if endpoint in host_lower:
            return platform
    return None


def is_skill_path(filepath: str) -> bool:
    """Check if a file path is inside an agent skill/plugin directory."""
    path_lower = filepath.lower().replace("\\", "/")
    return any(sp in path_lower for sp in AGENT_SKILL_PATHS)


def identify_agent_process(details: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Identify AI agent from process details. Returns name, framework, and category."""
    haystack = " ".join([
        str(details.get("name", "")),
        str(details.get("exe", "")),
        " ".join(details.get("cmdline", []) or []),
    ]).lower()

    for key, info in AGENT_SIGNATURES.items():
        if key in haystack:
            return {
                "name": info["name"],
                "framework": info["framework"],
                "category": info.get("category", AGENT_CATEGORY_GENERAL),
            }
    return None
