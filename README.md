# AgentDR — Agent Detection & Response Prototype

> An open-source prototype for detecting, monitoring, and responding to AI agent activity on endpoints, aligned with the **CoSAI AI Telemetry Framework (AITF)** and the [`girdav01/aitf`](https://github.com/girdav01/aitf) reference spec.

AgentDR is an early-stage research prototype that demonstrates what an *Endpoint Detection & Response* product looks like when the threat model expands to include autonomous AI agents — coding assistants, browser-use agents, multi-agent orchestrators, enterprise copilots, and rogue general-purpose agents (OpenClaw, AutoGPT, etc.). It captures rich AI-aware telemetry from monitored endpoints, classifies activity against community-maintained signature rules, and surfaces alerts through a Next.js analyst dashboard.

The project is organized into two cooperating components plus a shared, pluggable rule pack:

```
AgentDR/
├── adr_system/
│   ├── rust_agent/              ← Endpoint monitoring agent (Rust) — reference impl
│   │   ├── src/                 ← Monitors, ingest, exporters, policy, proxy, CLI
│   │   └── Cargo.toml
│   ├── cosai-community/         ← Shared CoSAI/AITF rule pack (signatures, endpoints, policies)
│   └── archive/
│       └── python-agent/        ← Original Python prototype (archived, not maintained)
├── adr_dashboard/
│   └── nextjs_space/            ← Analyst dashboard (Next.js 14 + Prisma + Postgres)
├── packaging/                   ← Signed installers: macOS .pkg, Windows MSI, Linux deb/rpm
├── mdm/                         ← MDM templates: Jamf, Intune, Kandji, Fleet
└── docs/                        ← Test plans, marketing, blog, conference deck
```

> **Note on the Python agent.** AgentDR began as a Python prototype. The
> endpoint agent has since been rewritten in **Rust** — it is faster,
> uses < 40 MB resident, has no interpreter dependency, and is the only
> actively maintained agent. The Python prototype is preserved under
> [`adr_system/archive/python-agent/`](adr_system/archive/python-agent/)
> for historical reference and is not built, tested, or shipped.

---

## Goals of the prototype

1. **Make AI agent activity observable.** Most EDRs can detect a process and a network connection, but cannot tell you that the process *is* Claude Code, that it just called the OpenAI API 47 times in 60 seconds, or that it dropped a Python skill file into `~/.openclaw/skills/`. AgentDR fills that gap.
2. **Demonstrate an OCSF Category 7 telemetry pipeline.** Every event the agent emits is shaped against the CoSAI/AITF schema so downstream SIEMs can consume it without a translation layer.
3. **Provide a reference rule pack.** The `cosai-community/` directory is a self-contained, JSON-driven, checksum-verified pack of agent signatures, AI endpoint patterns, messaging endpoints, and 20 detection rules — designed to be edited and extended without recompiling the agent.
4. **Show the analyst side.** The Next.js dashboard provides activity, alerts, analytics, logs, and policy management views over the captured events.

---

## Components

### 1. `adr_system/rust_agent/` — Endpoint Monitoring Agent

A cross-platform **Rust** agent (Windows, macOS, Linux) that runs on the monitored host. It is built around an async event bus: every monitor, ingest path and detector produces `EventRecord`s into a single channel; storage, the legacy server-push, the vendor exporters and the policy engine all consume from it.

**Monitors** (`src/monitors/`) — `file` (via `notify`), `process` (via `sysinfo`), `network`, `browser` (Chrome DevTools Protocol) and `kernel` (Linux NETLINK_AUDIT). See *[How AgentDR turns behavior into telemetry](#how-agentdr-turns-behavior-into-telemetry)* below for the full technique inventory.

**Ingest** (`src/ingest/`) — A loopback OTLP/HTTP server that decodes OpenTelemetry `gen_ai.*` semantic conventions straight into the AITF schema.

**MCP** (`src/mcp/`) — Model Context Protocol server inventory plus an stdio-proxy that captures every JSON-RPC message.

**Detection engine** (`src/detectors.rs`) — Stateful pattern detection implementing all 20 rules (`AITF-DET-001` → `AITF-DET-020`), plus credential-use attribution.

**Policy & response** (`src/policy/`, `src/proxy/`) — A YAML policy-as-code engine and an inline HTTP CONNECT proxy that can *block* agent egress, not just observe it.

**Exporters** (`src/exporters/`) — Ten SIEM/observability backends (Splunk, Datadog, Elastic, Chronicle, XSIAM, Snowflake, Sentinel, Wazuh, syslog, generic OCSF).

**CLI** (`src/main.rs`):

```
adr-agent start --watch ~/Projects      # foreground with live event stream
adr-agent verify                        # verify SHA-256 checksums of rule files
adr-agent update                        # refresh community rule pack
adr-agent hooks install all             # wire Claude Code / Cursor / Codex / Aider / OpenCode to OTLP
adr-agent agents list                   # multi-tool inventory: hooks, MCP, running PIDs per agent
adr-agent discovery scan                # auto-discover AI agents on this host
adr-agent discovery scan --apply        # ...and install hooks per [discovery].mode
adr-agent discovery prompt              # interactive: ask the user about each new agent
adr-agent mcp inventory                 # enumerate MCP server configs
adr-agent mcp wrap --name x -- <cmd>    # stdio-proxy + record an MCP server
adr-agent otlp                          # standalone OTLP collector
adr-agent policy list | policy test     # inspect / dry-run the policy pack
adr-agent proxy --allow anthropic.com   # standalone inline blocking proxy
adr-agent shell wrap --name s -- <cmd>  # record an agent shell session
```

Build it with `cd adr_system/rust_agent && cargo build --release`; the binary is `target/release/adr-agent`. Pre-built signed packages for all three OSes are produced by the release workflow in `.github/workflows/release.yml`.

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

## How AgentDR turns behavior into telemetry

AgentDR's job is to take *raw endpoint behavior* — a file opened, a syscall
made, an HTTP request attempted, a JSON-RPC frame sent to an MCP server —
and convert it into **normalized, SIEM-ready telemetry**: one `EventRecord`
per observed behavior, shaped against OCSF Category 7. Every technique below
feeds the **same async event bus**; the bus is what makes a credential read
from the file monitor, an OTLP span from Claude Code, and a blocked
connection from the inline proxy all come out the other end with the same
fields, the same `trace_id` discipline, and the same compliance mappings.

### The pipeline

```
 observation techniques            normalization              fan-out
 ─────────────────────             ─────────────              ───────
 file / process / network  ┐
 OTLP gen_ai.* ingest      │
 MCP inventory + stdio     ├──►  EventRecord  ──►  detection  ──►  JSONL store
 kernel audit              │     (OCSF Cat-7)      engine +       server push
 shell / TTY wrap          │     class_uid,        policy         10 exporters
 browser CDP               │     trace_id,         engine         inline proxy
 inline proxy              ┘     severity_id …                    decisions
```

Nothing downstream needs to know *which* technique produced an event — the
detector, the policy engine and every exporter operate purely on the
normalized `EventRecord`.

### Technique inventory

| # | Technique | What it observes | OS mechanism | Becomes |
|---|-----------|------------------|--------------|---------|
| 1 | **File-system watch** | create / modify / delete / move under watched dirs; writes to agent-skill paths and credential files | `inotify` (Linux), `FSEvents` (macOS), `ReadDirectoryChangesW` (Windows) via the `notify` crate | `class_uid 7002` agent action; `7006` on credential paths |
| 2 | **Process-table polling** | process start / stop; names, exe paths and command lines matched to AI-agent signatures | `/proc` (Linux), `libproc` (macOS), `ToolHelp` (Windows) via `sysinfo` | `class_uid 7002`; `agent_name` / `agent_framework` populated from `agent-signatures.json` |
| 3 | **Network observation** | outbound connections to AI provider & messaging hosts | mitm-style HTTP proxy *or* socket sampling + DNS | `class_uid 7001` (AI API) / `7007` (messaging) |
| 4 | **OTLP `gen_ai.*` ingest** | prompts, tool calls, token usage, approvals — emitted by the agents themselves | loopback OTLP/HTTP server; OpenTelemetry GenAI semantic conventions | `7001` inference, `7003` tool, `7004` MCP, `7007` approval |
| 5 | **Runtime hooks** | wires Claude Code / Cursor / Codex / Aider / OpenCode to emit (4) in the first place | edits each agent's own config (`settings.json`, `mcp.json`, `config.toml`, `opencode.json`) | enables technique 4 with semantic certainty (no guessing) |
| 6 | **MCP inventory** | which MCP servers are declared, where, with which transport and which secret env keys | scans 8 known config locations across every runtime | `class_uid 7004`, `activity_id 2 (Read)` |
| 7 | **MCP stdio interception** | every JSON-RPC request/response to a wrapped MCP server | `adr-agent mcp wrap` re-execs the server and proxies stdin/stdout | `class_uid 7004`; `tool_name` = JSON-RPC method |
| 8 | **Kernel audit** | syscall / path records from the OS audit subsystem | `NETLINK_AUDIT` multicast (Linux); EndpointSecurity / ETW posture on macOS / Windows | `class_uid 7002`, `activity_id 6 (Detect)` |
| 9 | **Shell / TTY wrap** | every command an agent shell-execs, plus its stdout / stderr | `adr-agent shell wrap` pipes stdin/stdout/stderr | `class_uid 7003`; input = medium risk, output = low |
| 10 | **Browser CDP attach** | page open / navigate / close by browser-use agents | polls the Chrome DevTools `/json` endpoint | `class_uid 7002` with destination URL |
| 11 | **Inline proxy decisions** | every CONNECT an agent attempts, allowed or denied | loopback HTTP CONNECT proxy consulted by `HTTPS_PROXY` | `7001/7002` on allow, `7008` BLOCKED on deny |
| 12 | **Credential attribution** | joins a credential-file read to the agent process responsible | 10-minute rolling window of agent `process_started` events | enriches the `AITF-DET-018` alert with a `candidate_agents` list |
| 13 | **Self-protection / watchdog** | hashes AgentDR's own config, the rule pack, the binary, and every installed runtime-hook config; fires when an AgentDR marker is removed or a tracked file disappears | periodic SHA-256 + marker presence check | `class_uid 7008` (critical) on evasion, optional self-heal that re-installs the hook |
| 14 | **Auto-discovery** | finds every AI agent on the host (PATH, install locations, hook configs, MCP entries, running PIDs) and decides what to monitor per `[discovery].mode` (interactive / policy / automatic / off) | runs on install, on startup, on schedule, on demand | hook installs + class_uid 7002 `discovery_scan_completed` events |

### From observation to a normalized event

Each technique constructs an `EventRecord` and fills the OCSF Category 7
fields it can attest to:

* **`class_uid` / `type_uid` / `activity_id`** — *what kind of behavior*
  this is (LLM inference, tool execution, MCP operation, data
  exfiltration …) and the verb (Create / Read / Update / Delete /
  Execute / Detect / Block).
* **`severity_id` / `risk_level` / `status_id`** — *how dangerous* and
  whether it succeeded, failed, or was **blocked**.
* **AI-specific identity** — `provider`, `model`, `agent_name`,
  `agent_framework`, `tool_name`, `mcp_server`, `token_usage`,
  `actor` (`{user, host, pid}`).
* **`trace_id` / `span_id`** — OpenTelemetry-style IDs. Techniques that
  see a real trace (OTLP, MCP) carry it through verbatim; the rest
  generate one. Detections inherit the `trace_id` of the event that
  triggered them, so a multi-step agent run reconstructs end-to-end.
* **`compliance` / `security_finding`** — OWASP LLM Top-10 and
  NIST AI-RMF mappings attached to every detection and policy hit.

### From a normalized event to a decision

Once an event is on the bus it is, in order:

1. **persisted** to a rotating JSONL store;
2. run through the **detection engine** — 20 stateful rules over sliding
   time windows (e.g. *rapid file modification*, *unusual API volume*,
   *credential access*) — each match emitting its own alert event;
3. run through the **policy engine** — YAML policy-as-code; each match
   emits a `class_uid 7008` Compliance Violation and can escalate to a
   **block**;
4. **fanned out** to the legacy server-push and to every enabled vendor
   exporter (Splunk, Datadog, Elastic, Chronicle, XSIAM, Snowflake,
   Sentinel, Wazuh, syslog, OCSF).

The result: behavior observed by *any* technique becomes a standardized
OCSF Category 7 record that lands in the analyst's SIEM — and, when a
policy says so, gets blocked at the proxy in the same pass.

---

## Self-protection and multi-tool monitoring

### Self-protection (watchdog)

AgentDR ships a built-in watchdog that defends its own footprint on the
endpoint — and in particular detects when a monitored AI agent tries to
*escape surveillance* by removing AgentDR's marker from its config.

What it tracks:

* The agent's own `config.toml`
* The AgentDR binary on disk
* The community rule pack (`cosai-community/rules/*.json`,
  `policies/*.json`, `policies/policies.yaml`)
* Every installed runtime-hook config (Claude Code, Cursor, Codex, Aider,
  OpenCode)

What it detects (per tick, default 30 s):

| Observation | Severity | Event |
|---|---|---|
| Hook config hash changed, AgentDR marker still present | `low` | `watchdog_config_changed` — likely operator edit |
| Hook config hash changed, marker MISSING (was present) | `critical` | **`watchdog_evasion_detected`** — class_uid 7008, status=BLOCKED |
| Tracked file deleted | `critical` | `watchdog_file_missing` |
| Agent config edited | `medium` | `watchdog_config_changed` |
| Rule / policy pack edited | `high` | `watchdog_rule_pack_changed` |
| Binary on disk replaced | `critical` | `watchdog_binary_changed` |

Configure under `[watchdog]`:

```toml
[watchdog]
enabled          = true
interval_seconds = 30
self_heal        = true   # on evasion, automatically re-install the missing hook
```

When `self_heal = true`, an evasion detection triggers an immediate
re-run of the matching `hooks install <agent>` so the marker (and the
OTLP wiring it carries) is restored within one tick.

### Multi-tool monitoring on a single host

Developers and AI engineers routinely run **several coding agents
side by side** — Claude Code in one terminal, Cursor in the IDE,
OpenCode for a quick session, Codex CLI in CI. AgentDR is designed for
this from the bus down:

* The process monitor matches every running process against every
  signature; no rule limits AgentDR to one agent at a time.
* Each runtime hook sets a distinct `OTEL_SERVICE_NAME`
  (`claude-code`, `cursor`, `codex`, `aider`, `opencode`), so the
  single loopback OTLP collector trivially demuxes per-agent.
* Every event carries `agent_name` + `agent_framework`, every UEBA
  baseline is keyed by `(host, user, agent)`, and the Sessions
  dashboard joins activity across multiple agents through `trace_id`.

To see the live picture for the current host:

```bash
adr-agent agents list                 # human-readable table
adr-agent agents list --json          # machine-readable for ops automation
```

The table shows, per agent: whether its binary is on `$PATH`, whether
AgentDR's hook is installed (and to what endpoint), which MCP servers
it has configured, and which PIDs (if any) are running right now.

### Auto-discovery (Tier 8)

Personal endpoints, developer laptops, CI runners and managed
enterprise fleets each want a different policy for "*which* AI agents
on this host should AgentDR actually monitor?" The discovery subsystem
answers that question one of four ways, set under `[discovery].mode`:

| mode | Behaviour |
|---|---|
| `off`         | Scan and report only; never install hooks automatically |
| `interactive` | Prompt the local user via stdin for each newly-found agent (TTY required) |
| `policy`      | Apply `cosai-community/policies/discovery.yaml` (default) |
| `automatic`   | Install hooks for every supported agent that's found |

Triggers:

* **On install** — the macOS `.pkg` postinstall and Linux `.deb` postinst
  both run `adr-agent discovery scan --apply` so the agent self-configures
  during fleet rollout.
* **On startup** — the engine runs a scan at start when
  `[discovery].scan_on_start = true` (default).
* **On schedule** — periodic re-scan every `[discovery].scan_interval_hours`
  (default 24 h), so an agent that gets installed *after* AgentDR is
  picked up automatically.
* **On demand** — `adr-agent discovery scan [--apply]` from the shell.

Evidence sources per agent: `$PATH` binary, well-known install locations
(macOS `.app`, `/opt/`, `~/.local/bin/`, Windows `Program Files`), hook
config presence (including the unmanaged case — "user has Aider's
`~/.aider.conf.yml` but no AgentDR hook"), MCP entries in
runtime-specific configs, and currently-running matched PIDs. Confidence
scores aggregate across sources.

User decisions are persisted to `<root>/runtime/discovery-state.json`
so the user is never asked twice. Operators inspect / override with:

```bash
adr-agent discovery status              # show recorded decisions
adr-agent discovery prompt              # interactive prompt loop
```

The default policy ships with safe choices: monitor every coding agent
(Claude Code, Cursor, Codex, Aider, OpenCode); prompt before monitoring
browser-use agents (Computer Use, Operator, Browser Use); skip enterprise
copilots (M365 Copilot et al.) until an admin opts them in.

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
| OpenCode | OpenCode CLI | `opencode` |

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

To extend coverage, edit `adr_system/cosai-community/rules/agent-signatures.json`, then regenerate `checksums.sha256` with `scripts/generate-checksums.sh`. Run `adr-agent verify` to confirm the agent will accept the update.

---

## AI Telemetry: CoSAI / AITF schema

AgentDR's telemetry follows the **CoSAI AI Telemetry Framework (AITF)** as described in [`girdav01/aitf`](https://github.com/girdav01/aitf), which defines an OCSF-style **Category 7** for AI-specific events. Every `EventRecord` (see `adr_system/rust_agent/src/models.rs`) is shaped against this schema so that events are SIEM-ready without a translation layer.

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

Defined in `adr_system/cosai-community/policies/detection-rules.json` and wired into the engine via `adr_system/rust_agent/src/models.rs::detection_rules()`:

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
cd adr_system/rust_agent
cargo build --release
./target/release/adr-agent start --watch ~/Documents
```

Or install a pre-built signed package — `brew install agentdr` (macOS),
`scoop install agentdr` (Windows), or the `.deb` / `.rpm` (Linux). Then
wire your coding agents to the loopback OTLP collector in one command:

```bash
adr-agent hooks install all --endpoint http://127.0.0.1:4318
```

Step-by-step demo walkthroughs for each OS live in
[`docs/test-plans/`](docs/test-plans/).

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

Add a `server_push` block to `config.toml` (next to the agent's `--root`),
or enable any of the ten vendor exporters under `[exporters.*]`:

```toml
[server_push]
enabled  = true
endpoint = "http://localhost:3000/api/sync"
api_key  = "<org api key from dashboard>"
```

### 4. Refresh and verify the rule pack

```bash
adr-agent update    # pull latest cosai-community rules
adr-agent verify    # SHA-256 integrity check
```

---

## Status & limitations

AgentDR is **research-grade software**, not a hardened commercial EDR.
Current state and known caveats:

- **Tool / MCP execution events** are captured directly via the OTLP
  ingest path (technique 4) and the MCP stdio-proxy (technique 7) when
  the runtime hooks are installed; without hooks, AgentDR still infers
  them from process and file-system signals, but with lower fidelity.
- **Token / cost fields** are populated from OTLP `gen_ai.usage.*`
  attributes; agents that don't emit them leave those fields empty.
- **macOS / Windows kernel telemetry** ships as a documented posture
  (EndpointSecurity sidecar / ETW providers) rather than a built-in
  collector — only Linux `NETLINK_AUDIT` runs in-process today.
- **Prompt-injection scoring (7005)** emits events but does not yet
  classify prompt content — AgentDR observes and forwards; correlation
  is left to the SIEM.
- **Inline TLS** is hostname-level (CONNECT SNI) only; AgentDR does not
  ship an MITM CA.

Multi-host correlation, per-agent UEBA baselining, kill-chain replay,
the ten vendor exporters, and inline policy blocking are all implemented
— see the technique inventory above.

Contributions to the rule pack — especially new agent signatures, AI
endpoint patterns, and policy-as-code rules — are welcome via the
[`cosai-community/docs/CONTRIBUTING.md`](adr_system/cosai-community/docs/CONTRIBUTING.md) guide.

## License

Apache-2.0, aligned with CoSAI open-source governance.
