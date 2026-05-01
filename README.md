# AgentDR — Agent Detection & Response Prototype

> An open-source prototype for detecting, monitoring, and responding to AI agent activity on endpoints, aligned with the **CoSAI AI Telemetry Framework (AITF)** and the [`girdav01/aitf`](https://github.com/girdav01/aitf) reference spec.

AgentDR is an early-stage research prototype that demonstrates what an *Endpoint Detection & Response* product looks like when the threat model expands to include autonomous AI agents — coding assistants, browser-use agents, multi-agent orchestrators, enterprise copilots, and rogue general-purpose agents (OpenClaw, AutoGPT, etc.). It captures rich AI-aware telemetry from monitored endpoints, classifies activity against community-maintained signature rules, and surfaces alerts through a Next.js analyst dashboard.

The project is organized into two cooperating components plus a shared, pluggable rule pack:

```
AgentDR/
├── adr_system/                  ← Endpoint monitoring agent (Python)
│   ├── agent/                   ← Monitors, detectors, engine, CLI
│   ├── cosai-community/         ← Shared CoSAI/AITF rule pack (signatures, endpoints, policies)
│   ├── config.json              ← Runtime configuration
│   └── requirements.txt
└── adr_dashboard/
    └── nextjs_space/            ← Analyst dashboard (Next.js 14 + Prisma + Postgres)
```

---

## Goals of the prototype

1. **Make AI agent activity observable.** Most EDRs can detect a process and a network connection, but cannot tell you that the process *is* Claude Code, that it just called the OpenAI API 47 times in 60 seconds, or that it dropped a Python skill file into `~/.openclaw/skills/`. AgentDR fills that gap.
2. **Demonstrate an OCSF Category 7 telemetry pipeline.** Every event the agent emits is shaped against the CoSAI/AITF schema so downstream SIEMs can consume it without a translation layer.
3. **Provide a reference rule pack.** The `cosai-community/` directory is a self-contained, JSON-driven, checksum-verified pack of agent signatures, AI endpoint patterns, messaging endpoints, and 20 detection rules — designed to be edited and extended without recompiling the agent.
4. **Show the analyst side.** The Next.js dashboard provides activity, alerts, analytics, logs, and policy management views over the captured events.

---

## Components

### 1. `adr_system/` — Endpoint Monitoring Agent

A cross-platform Python agent (Windows, macOS, Linux) that runs on the monitored host. It is composed of four cooperating monitors and a detection engine.

**File monitor** (`agent/monitors/file_monitor.py`) — Uses `watchdog` to capture create/modify/delete/move events on configured directories. Flags files that land in known agent-skill paths (`.openclaw/skills`, `.autogpt/plugins`, `skills/`, etc.) and credential-sensitive paths (`.env`, `id_rsa`, `.aws/credentials`, `service-account.json`, ...).

**Network monitor** (`agent/monitors/network_monitor.py`) — Two operating modes:
- **Proxy mode (preferred):** spawns `mitmproxy` with the `mitm_addon.py` add-on so HTTPS calls to AI provider domains (OpenAI, Anthropic, Google, DeepSeek, Mistral, Ollama, Microsoft Copilot, ServiceNow, SAP AI, Browserbase, etc.) are decoded with method, host, path, and client IP.
- **Fallback mode:** if the proxy fails to start, the agent samples sockets via `psutil` plus DNS resolution to record connections to the same target hosts on a best-effort basis.

**Process monitor** (`agent/monitors/process_monitor.py`) — Polls the process table and emits `process_started` / `process_ended` events. Process names, executables, and command lines are matched against `cosai-community/rules/agent-signatures.json` to classify which AI agent is running.

**Detection engine** (`agent/detectors.py`) — Stateful pattern detection over the event stream. Implements rules `AITF-DET-009` through `AITF-DET-020` (rapid file modifications, unusual API volume, large/bulk deletions, malicious skill loads, unauthorized messaging, shell execution by an agent, credential access, cross-platform data relay, and unvetted skill installation). Every detection emits a CoSAI-compliant alert with OCSF fields, an OWASP LLM Top-10 mapping, and a NIST AI-RMF compliance reference.

**Storage & shipping** — Events land in `agent/logs/events.jsonl` (rotated). An optional `server_push` block in `config.json` ships batches to an HTTPS collector (the dashboard's `/api/sync` endpoint or any SIEM ingest URL).

**CLI** (`agent/main.py`):

```
python -m agent.main start              # foreground with live event stream
python -m agent.main start --daemon     # background daemon
python -m agent.main stop                # stop daemon
python -m agent.main status              # daemon status
python -m agent.main stats               # summarise events.jsonl
python -m agent.main config show
python -m agent.main config add-watch ~/Projects
python -m agent.main config set detection.unusual_api_call_volume.threshold_count 80
python -m agent.main update              # refresh community rule pack
python -m agent.main verify              # verify SHA-256 checksums of rule files
```

### 2. `adr_dashboard/nextjs_space/` — Analyst Dashboard

A Next.js 14 (App Router) + TypeScript + Tailwind + shadcn/ui application backed by Prisma and PostgreSQL. It provides:

- **Dashboard** — risk summary, agent-activity heatmap, recent high-severity events.
- **Activity / Logs** — searchable, filterable raw event timeline.
- **Alerts** — triage view of detection rule firings.
- **Analytics** — timeline charts, agent distribution, event-type distribution (Recharts/Plotly).
- **Policies** — enable/disable detection rules and adjust thresholds per organization.
- **Settings** — storage retention, archival, multi-tenant org configuration.
- **Auth** — NextAuth with Prisma adapter (org/role: owner / admin / analyst / viewer).

The Prisma schema (`prisma/schema.prisma`) carries the full OCSF Category 7 field set on the `Event` model (`classUid`, `typeUid`, `activityId`, `severityId`, `provider`, `model`, `agentName`, `agentFramework`, `toolName`, `mcpServer`, `actor`, `compliance`, `securityFinding`, `tokenUsage`, `costInfo`, `traceId`, `spanId`).

Events are ingested by the agent's `server_push` POSTing to `/api/sync`. Alerts are exposed at `/api/alerts`, recent events at `/api/events/recent`.

### 3. `adr_system/cosai-community/` — Shared CoSAI Rule Pack

A versioned, JSON-only, checksum-verified rule pack consumed by the agent at runtime. Operators can patch new agent signatures or AI endpoints without redeploying binaries.

```
cosai-community/
├── rules/
│   ├── agent-signatures.json      # process patterns → agent name/framework/category/risk
│   ├── ai-endpoints.json          # hostname patterns → AI provider/model
│   └── messaging-endpoints.json   # hostname patterns → messaging platform
├── policies/
│   └── detection-rules.json       # 20 default detection rules with severity/category
├── scripts/generate-checksums.sh
├── checksums.sha256               # SHA-256 manifest verified by `agent verify`
└── docs/CONTRIBUTING.md
```

---

## Target agents supported

The agent rule pack ships with detectors for five categories. Each entry below shows the **agent name** → **framework** → **default risk** assigned by the CoSAI signature.

### Coding assistants (low-risk by default)

| Agent | Framework | Process patterns |
|---|---|---|
| Cursor | Cursor IDE | `cursor` |
| Claude Code | Anthropic CLI | `claude`, `claude_desktop` |
| Codex CLI | OpenAI CLI | `codex` |
| GitHub Copilot | VSCode Extension | `copilot` |
| Aider | Aider | `aider` |
| Devin | Cognition | `devin` |
| Windsurf | Codeium | `windsurf` |
| Cline | VSCode Extension | `cline` |
| Augment Code | VSCode Extension | `augment` |
| Continue.dev | VSCode Extension | `continue` |

### General-purpose autonomous agents (medium / high risk)

| Agent | Framework | Risk |
|---|---|---|
| OpenClaw | OpenClaw Runtime | high |
| NemoClaw | NVIDIA NemoClaw | medium |
| AutoGPT | AutoGPT | high |
| BabyAGI | BabyAGI | medium |
| SuperAGI | SuperAGI | medium |
| ChatGPT (desktop) | OpenAI | medium |

### Workflow / orchestration frameworks

LangChain, CrewAI, Microsoft AutoGen, LlamaIndex, HuggingFace SmolAgents.

### Enterprise / productivity copilots

M365 Copilot, Edge Copilot, Windows Copilot, Copilot Studio (high), Bing Copilot, ServiceNow CLI / MID Server / Now Assist / Virtual Agent, SAP GUI, SAP BTP CLI, SAP Joule, SAP Integration Agent.

### Browser-automation agents (high-risk by default)

Claude Computer Use, OpenAI Operator, Browser Use, Browserbase, Stagehand.

To extend coverage, edit `adr_system/cosai-community/rules/agent-signatures.json`, then regenerate `checksums.sha256` with `scripts/generate-checksums.sh`. Run `python -m agent.main verify` to confirm the agent will accept the update.

---

## AI Telemetry: CoSAI / AITF schema

AgentDR's telemetry follows the **CoSAI AI Telemetry Framework (AITF)** as described in [`girdav01/aitf`](https://github.com/girdav01/aitf), which defines an OCSF-style **Category 7** for AI-specific events. Every `EventRecord` (see `adr_system/agent/models.py`) is shaped against this schema so that events are SIEM-ready without a translation layer.

### Event classes (`class_uid`)

| `class_uid` | Class name | What AgentDR emits here |
|---:|---|---|
| 7001 | LLM Inference | Decoded LLM request/response metadata (provider, model, token counts, cost) |
| 7002 | Agent Action | Process start/stop, file activity attributed to a known agent |
| 7003 | Tool Execution | Shell commands and tool calls invoked by an agent |
| 7004 | MCP Operation | MCP server interactions, plugin/skill loads |
| 7005 | Prompt Injection | Suspicious prompt content patterns |
| 7006 | Data Exfiltration | Bulk deletions, credential file access, sensitive data egress |
| 7007 | Permission Escalation | Boundary violations, privileged messaging access |
| 7008 | Compliance Violation | Drift from configured policy / framework requirements |
| 7009 | Guardrail Event | Guardrail triggers and insecure-output handling |
| 7010 | Cost Anomaly | Unusual API volume, token-spend spikes |

### Common OCSF fields on every event

`timestamp`, `class_uid`, `type_uid` (= `class_uid * 100 + activity_id`), `activity_id` (Create=1, Read=2, Update=3, Delete=4, Execute=5, Detect=6, Block=7), `severity_id` (Informational=1 → Critical=5, mapped from `risk_level`), `status_id` (Success/Failure/Blocked/Unknown), `message`.

### AI-specific fields

`provider` (OpenAI, Anthropic, Google, Azure OpenAI, DeepSeek, Mistral, Ollama, Microsoft Copilot, ServiceNow, SAP AI, Browserbase, ...), `model`, `agent_name`, `agent_framework`, `tool_name`, `mcp_server`, `actor` (`{user, pid}`), `token_usage`, `cost_info`.

### Compliance / security finding fields

`security_finding` (`{rule_id, title, severity, owasp_llm}`), `compliance` (frameworks list — OWASP LLM Top-10 and NIST AI-RMF — plus the rule's specific OWASP mapping).

### Distributed tracing

Every event carries an OpenTelemetry-style `trace_id` (32 hex) and `span_id` (16 hex). Detection alerts inherit the `trace_id` of the triggering event so a multi-step agent workflow can be reconstructed end-to-end.

### Detection rule catalog (`AITF-DET-001` → `AITF-DET-020`)

Defined in `adr_system/cosai-community/policies/detection-rules.json` and wired into the engine via `agent/models.py::DETECTION_RULES`:

| ID | Rule | Category | OWASP | OCSF Class |
|---|---|---|---|---:|
| AITF-DET-001 | Unusual Token Usage / Prompt Injection Detected | Inference | LLM01 | 7005 |
| AITF-DET-002 | Model Switching Attack / Sensitive Data in Output | Inference | LLM02 | 7006 |
| AITF-DET-003 | Prompt Injection Attempt / Excessive Token Usage | Inference | LLM04 | 7010 |
| AITF-DET-004 | Excessive Cost Spike / Unauthorized Tool Execution | Inference | LLM05 | 7003 |
| AITF-DET-005 | Agent Loop Detection / Excessive Agency | Agent | LLM08 | 7002 |
| AITF-DET-006 | Unauthorized Agent Delegation / Supply Chain Anomaly | Agent | LLM03 | 7004 |
| AITF-DET-007 | Agent Session Hijack / Insecure Output Handling | Agent | LLM02 | 7009 |
| AITF-DET-008 | Excessive Tool Calls / Model DoS | Agent | LLM04 | 7010 |
| AITF-DET-009 | Rapid File Modifications | MCP/Tool / Agent | LLM08 | 7002 |
| AITF-DET-010 | Bulk Data Deletion | MCP/Tool | LLM06 | 7006 |
| AITF-DET-011 | Permission Boundary Violation | MCP/Tool | LLM05 | 7007 |
| AITF-DET-012 | Unusual API Volume | Security | LLM04 | 7010 |
| AITF-DET-013 | MCP Server Abuse / Jailbreak Escalation | Security | LLM05 | 7004 |
| AITF-DET-014 | Compliance Drift / Supply Chain Compromise | Security | LLM09 | 7008 |
| AITF-DET-015 | Malicious Skill / Plugin Loaded | Agent/Plugin | LLM03 | 7004 |
| AITF-DET-016 | Unauthorized Messaging Channel Access | Agent/Comms | LLM05 | 7007 |
| AITF-DET-017 | Shell Command Execution by Agent | Agent/System | LLM08 | 7003 |
| AITF-DET-018 | Agent Credential / Secret Access | Security | LLM06 | 7006 |
| AITF-DET-019 | Cross-Platform Data Relay | Security | LLM02 | 7006 |
| AITF-DET-020 | Unvetted Skill Installation | Agent/Plugin | LLM03 | 7004 |

### Sample event (JSONL)

```json
{
  "timestamp": "2026-05-01T14:22:08.421+00:00",
  "event_type": "process_started",
  "class_uid": 7002,
  "type_uid": 700201,
  "activity_id": 1,
  "severity_id": 3,
  "status_id": 1,
  "risk_level": "medium",
  "message": "Process started: openclaw",
  "agent_name": "OpenClaw",
  "agent_framework": "OpenClaw Runtime",
  "agent_detected": "OpenClaw",
  "actor": {"user": "david", "pid": 28471},
  "details": {"pid": 28471, "name": "openclaw", "exe": "/usr/local/bin/openclaw"},
  "trace_id": "9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d",
  "span_id": "1a2b3c4d5e6f7a8b",
  "source": "process_monitor"
}
```

### Sample alert (JSONL)

```json
{
  "timestamp": "2026-05-01T14:22:14.902+00:00",
  "event_type": "alert_credential_access",
  "class_uid": 7006,
  "type_uid": 700606,
  "activity_id": 6,
  "severity_id": 5,
  "risk_level": "critical",
  "message": "[AITF-DET-018] Agent Credential / Secret Access",
  "agent_detected": "credential_harvesting",
  "details": {
    "path": "/Users/david/.aws/credentials",
    "event_type": "file_read",
    "rule_id": "AITF-DET-018",
    "rule_name": "Agent Credential / Secret Access",
    "owasp_category": "LLM06"
  },
  "security_finding": {
    "rule_id": "AITF-DET-018",
    "title": "Agent Credential / Secret Access",
    "severity": "critical",
    "owasp_llm": "LLM06"
  },
  "compliance": {
    "frameworks": ["OWASP-LLM-Top10", "NIST-AI-RMF"],
    "mappings": {"OWASP-LLM-Top10": "LLM06"}
  },
  "trace_id": "9b7f0c8d2e1a4f5b6c7d8e9f0a1b2c3d",
  "span_id": "f0e1d2c3b4a59687",
  "source": "detector"
}
```

---

## How to use it

### 1. Run the agent locally

```bash
cd adr_system
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m agent.main config add-watch ~/Documents
python -m agent.main start
```

For HTTPS interception, configure your monitored app to use `127.0.0.1:8081` and trust the mitmproxy CA. If proxy mode fails, the agent falls back to socket sampling automatically.

### 2. Run the dashboard locally

```bash
cd adr_dashboard/nextjs_space
yarn install
# set DATABASE_URL and NEXTAUTH_SECRET in .env (Postgres)
npx prisma migrate deploy
yarn dev
```

The dashboard runs on `http://localhost:3000`. Sign up to create an organization, then set the agent's `server_push.endpoint` to `http://localhost:3000/api/sync` so events flow through.

### 3. Push agent events to the dashboard

```bash
python -m agent.main config set server_push.enabled true
python -m agent.main config set server_push.endpoint "http://localhost:3000/api/sync"
python -m agent.main config set server_push.api_key "<org api key from dashboard>"
```

### 4. Refresh and verify the rule pack

```bash
python -m agent.main update    # pull latest cosai-community rules
python -m agent.main verify    # SHA-256 integrity check
```

---

## Status & limitations

This is a **prototype**, not a production EDR. Known caveats:

- **Inference content (7001, 7005)** is currently scaffolded; the proxy add-on captures request metadata but does not yet score prompts for injection or extract token counts from response bodies.
- **Tool / MCP execution events** require an in-process hook in the host agent runtime; AgentDR currently infers these from process and file-system signals.
- **Cost / token usage** fields are present on the schema but not yet populated by the proxy.
- **Alert deduplication** is per-process / per-window only; multi-host correlation lives in the dashboard layer and is not yet implemented.

Contributions to the rule pack — especially new agent signatures and AI endpoint patterns — are welcome via the [`cosai-community/docs/CONTRIBUTING.md`](adr_system/cosai-community/docs/CONTRIBUTING.md) guide.

## License

Apache-2.0, aligned with CoSAI open-source governance.
