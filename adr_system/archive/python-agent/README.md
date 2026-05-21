> ## ⚠️ ARCHIVED
>
> This is the **original Python prototype** of the AgentDR endpoint agent.
> It has been superseded by the Rust agent at
> [`adr_system/rust_agent/`](../../rust_agent/), which is now the
> reference implementation and the only actively maintained endpoint
> agent. The Python version is kept here for historical reference and is
> **not built, tested, or shipped**.
>
> All current capabilities — OTLP ingest, runtime hooks, MCP capture,
> vendor exporters, policy-as-code, the inline blocking proxy, kernel /
> shell / browser telemetry, and credential attribution — live in the
> Rust agent. See the repository-root `README.md`.

---

# ADR Monitoring Agent (Windows + macOS)

Cross-platform Python monitoring agent for ADR (Agent Detection & Response) prototype.

## Features

- **File System Monitoring**: create/modify/delete/move events using `watchdog`
- **Network Monitoring**:
  - **Primary mode**: HTTP(S) interception with `mitmproxy` for AI API domains
  - **Fallback mode**: best-effort connection sampling using `psutil` + DNS resolution
- **Process Monitoring**: process start/stop tracking with basic AI-agent heuristics
- **Pattern Detection Engine**:
  - Rapid file modifications (default: >10 unique files in 60s)
  - Unusual API call volume (default: >40 calls in 60s)
  - Large file deletions (single large file and bulk deletion windows)
- **Storage**:
  - JSONL event logging with rotation
  - Event schema: `timestamp`, `event_type`, `details`, `risk_level`, `agent_detected`
- **Optional Server Push**:
  - Batched POST of events to a configurable server endpoint

## Project Structure

```text
/home/ubuntu/adr_system/
├── agent/
│   ├── main.py
│   ├── engine.py
│   ├── config_manager.py
│   ├── detectors.py
│   ├── storage.py
│   ├── service.py
│   ├── monitors/
│   │   ├── file_monitor.py
│   │   ├── network_monitor.py
│   │   └── process_monitor.py
│   ├── logs/
│   └── runtime/
├── config.json
├── requirements.txt
└── README.md
```

## Installation

### 1) Create virtual environment

#### macOS
```bash
cd /path/to/adr_system
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

#### Windows (PowerShell)
```powershell
cd C:\path\to\adr_system
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2) Configure

Edit `config.json`:
- `watch_directories`
- `network_monitor.ai_api_endpoints`
- `detection` thresholds
- `server_push` options (optional)

## CLI Usage

Run from project root:

```bash
python -m agent.main <command>
```

### Commands

- `start` - start monitoring in foreground (real-time feed)
- `start --daemon` - start in background
- `stop` - stop daemon mode process
- `status` - show daemon status
- `stats` - summarize event counts from JSONL logs
- `config` - configure settings

### Config subcommands

```bash
python -m agent.main config show
python -m agent.main config add-watch ~/Projects
python -m agent.main config remove-watch ~/Projects
python -m agent.main config set detection.unusual_api_call_volume.threshold_count 80
python -m agent.main config set server_push.enabled true
python -m agent.main config set server_push.endpoint "https://your-server.example.com/adr/events"
```

## Network Interception Notes (mitmproxy mode)

Default network mode is `proxy`.

1. Start agent.
2. Configure monitored app/system proxy to `127.0.0.1:8081` (or configured host/port).
3. Install/trust mitmproxy CA certificate on target machine for HTTPS decryption.

If proxy startup fails, the agent switches to fallback connection-sampling mode automatically.

## Event Format (JSONL)

Example:

```json
{"timestamp":"2026-05-01T12:34:56.123456+00:00","event_type":"network_request","details":{"host":"api.openai.com","method":"POST","path":"/v1/responses"},"risk_level":"low","agent_detected":null}
```

## Risk Levels

- `low`: normal telemetry
- `medium`: suspicious but not urgent
- `high`: likely malicious or risky behavior
- `critical`: severe and immediate-response pattern

## Production Hardening Recommendations

- Run as a least-privilege OS user
- Restrict outbound event push endpoint with TLS + auth
- Rotate API keys used for `server_push`
- Forward JSONL events into SIEM for central analysis
- Add signed update mechanism for agent binaries/packages

## Troubleshooting

- If `mitmdump` is missing, ensure `mitmproxy` installed in active venv
- On macOS, extra permissions may be needed for process/network visibility
- On Windows, run shell with appropriate privileges for full process/network telemetry
