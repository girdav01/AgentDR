# CoSAI Community Detection Rules

> **Coalition for Secure AI** — Community-maintained detection signatures, endpoint patterns, and policies for the Agent Detection & Response (ADR) framework.

## Structure

```
cosai-community/
├── rules/
│   ├── agent-signatures.json      # Process-name patterns to identify AI agents
│   ├── ai-endpoints.json           # AI provider API endpoint hostname patterns
│   └── messaging-endpoints.json    # Messaging platform endpoint patterns
├── policies/
│   └── detection-rules.json        # Default OCSF Category 7 detection rules
├── docs/
│   └── CONTRIBUTING.md             # How to contribute new signatures/rules
└── README.md                       # This file
```

## Usage

All rule files are JSON and follow a versioned schema. Consuming agents (Python, Rust, or the ADR Dashboard) load these files at runtime so signatures can be updated **without rebuilding** the agents.

### Agent Signatures (`rules/agent-signatures.json`)

Each entry maps a unique `id` to one or more `process_patterns` (substrings matched against running process names, executables, and command lines):

```json
{
  "id": "openclaw",
  "name": "OpenClaw",
  "framework": "OpenClaw Runtime",
  "category": "general",
  "risk": "high",
  "process_patterns": ["openclaw", "moltbot", "clawdbot"]
}
```

### AI Endpoint Signatures (`rules/ai-endpoints.json`)

Matches outbound HTTP connections to AI inference APIs:

```json
{
  "patterns": ["openai", "api.openai.com"],
  "provider": "OpenAI",
  "model": "gpt-4o"
}
```

The optional `requires_also` field means **both** the main pattern AND the specified string must appear (used for Azure OpenAI to distinguish from plain Azure traffic).

### Detection Rules (`policies/detection-rules.json`)

Pre-built threat-detection policies aligned with OCSF Category 7 event classes:

```json
{
  "id": "AITF-DET-003",
  "name": "Prompt Injection Attempt",
  "category": "Inference",
  "severity": "critical",
  "enabled": true
}
```

## Agent Categories

| Category     | Icon | Description |
|-------------|------|-------------|
| `coding`     | 💻   | AI coding assistants (Cursor, Claude Code, Copilot) |
| `general`    | 🤖   | Autonomous general-purpose agents (OpenClaw, AutoGPT) |
| `workflow`   | ⚙️   | Multi-agent orchestrators (LangChain, CrewAI) |
| `enterprise` | 🏢   | Enterprise productivity agents (Copilot, ServiceNow, SAP) |
| `browser`    | 🌐   | Agentic browser automation (Claude Computer Use, Operator) |

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for contribution guidelines.

## License

Apache-2.0 — Aligned with CoSAI open-source governance.
