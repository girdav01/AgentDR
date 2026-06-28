# LLM Guard reverse proxy & forward-proxy enrichment

AgentDR ships **two** complementary proxies under `src/proxy/`. They protect
traffic in opposite directions and are configured independently.

| | Forward CONNECT proxy | LLM Guard reverse proxy |
|---|---|---|
| Module | `src/proxy/mod.rs` (`InlineProxy`) | `src/proxy/reverse.rs` (`Guard`) |
| Config | `[proxy]` | `[llm_guard]` |
| Direction | Agent → **remote** LLM/API hosts (egress) | Client → **local** model backend (ingress) |
| Sees bodies? | No (HTTPS tunnelled via `CONNECT`) | Yes (terminates HTTP, inspects req/resp) |
| Default | disabled | disabled |

Both are opt-in (`enabled = false`) and emit the same OCSF / AITF events as the
rest of AgentDR via the shared event bus.

---

## 1. Forward CONNECT proxy enrichment (`[proxy]`)

The existing inline blocking proxy still does host allow-listing + policy-engine
decisions on every `CONNECT`. It now additionally records **caller
provenance**, can **authenticate** callers, and can **rate-limit** them. Because
the connection is an opaque TLS tunnel, enrichment works on connection metadata
and proxy headers — never on request bodies.

```toml
[proxy]
enabled = false
bind = "127.0.0.1:8080"
allowlist = []          # substring host allow-list (case-insensitive)
provenance = true       # resolve PID / exe / known-agent for each connection

# Optional auth. Empty tokens + jwt.enabled=false  =>  observe-only (no creds
# required), so it stays a drop-in for existing HTTPS_PROXY clients.
auth_tokens = []        # Proxy-Authorization: Bearer <key>  OR  X-API-Key: <key>

[proxy.jwt]
enabled = false
secret  = ""            # HS256 shared secret
issuer  = ""            # optional expected iss
audience = ""           # optional expected aud

# OFF by default so it never throttles chatty browser/agent clients.
[proxy.rate_limits]
enabled = false
requests_per_minute = 120
burst = 30
```

Behaviour:

1. **Provenance** — when `provenance = true`, AgentDR resolves the local process
   that opened the connection (PID / executable / command line, Linux via
   `/proc`) and attributes it to a known AI agent from the signature table.
   Emitted events gain an `actor` object plus `agent_name` / `agent_framework`.
2. **Auth** — if any `auth_tokens` are set or `jwt.enabled = true`, a missing /
   invalid credential is rejected with **`407 Proxy Authentication Required`**
   and a `proxy_auth_denied` event (`ai_operation = identity`).
3. **Rate limit** — when enabled, a per-caller sliding window (keyed by auth
   subject, else PID/peer) returns **`429`** and a `proxy_rate_limited`
   guardrail event on breach.
4. **Policy + allow-list** — unchanged; a denied host is blocked and a
   `compliance_violation` finding is emitted.

Run standalone:

```
adr-agent proxy --allow anthropic.com     # CLI overrides bind/allowlist on [proxy]
```

---

## 2. LLM Guard reverse proxy (`[llm_guard]`)

Put the guard **in front of** your local model servers and point clients at it
instead of the backend. Because it terminates HTTP, it can inspect prompts and
responses.

```toml
[llm_guard]
enabled = false
listen_address = "127.0.0.1:8011"
auth_tokens = []                      # Authorization: Bearer <key>  OR  X-API-Key
health_check_interval_seconds = 30    # 0 disables the background poller
max_body_bytes = 8388608             # 8 MiB request-body cap (413 over limit)
upstream_timeout_seconds = 120

# Requests route by route_prefix (longest match wins); the matched prefix is
# stripped before forwarding. An empty prefix is the default backend.
[[llm_guard.backends]]
name = "ollama"
kind = "ollama"
url = "http://127.0.0.1:11434"
route_prefix = "/ollama"
health_path = "/api/tags"

[[llm_guard.backends]]
name = "lmstudio"
kind = "lmstudio"
url = "http://127.0.0.1:1234"
route_prefix = "/lmstudio"
health_path = "/v1/models"

[[llm_guard.backends]]
name = "llamacpp"
kind = "llamacpp"
url = "http://127.0.0.1:8080"
route_prefix = "/llamacpp"
health_path = "/health"

[llm_guard.jwt]
enabled = false
secret = ""
issuer = ""
audience = ""

[llm_guard.rate_limits]
enabled = true
requests_per_minute = 120
burst = 30

[llm_guard.monitoring]
enabled = true
detect_prompt_injection = true
detect_pii = true
track_tokens = true
block_on_injection = false   # alert-only by default (still forwarded)
block_on_pii = false
max_prompt_chars = 512       # prompt chars retained in events (never the full prompt)
```

### Request lifecycle

```
client ─▶ [provenance] ─▶ [auth 401] ─▶ [rate-limit 429] ─▶ [route 502]
       ─▶ [read body ≤max 413] ─▶ [inspect prompt → 403 if block_on_*]
       ─▶ forward to backend ─▶ [read response] ─▶ [extract token usage]
       ─▶ emit observation ─▶ relay response to client
```

- **Routing** — e.g. `POST /ollama/api/generate` → `http://127.0.0.1:11434/api/generate`.
- **Auth** — missing/invalid credential → **`401 Unauthorized`**. Empty
  `auth_tokens` + `jwt.enabled = false` ⇒ observe-only (nothing rejected).
- **Rate limit** — per-key sliding window → **`429`**.
- **Content inspection** — prompts are extracted from common shapes
  (OpenAI `messages[]`, Ollama `prompt`, plain `input`). Injection / PII matches
  emit an OCSF Detection Finding (`class_uid 2004`, `ai_operation`
  `prompt_injection` / `data_exfiltration`). With `block_on_* = true` the
  request is rejected with **`403`** before reaching the backend; otherwise it is
  forwarded and only a finding is raised (alert-only).
- **Token usage** — parsed from the upstream response (OpenAI
  `usage.{prompt,completion,total}_tokens`, Ollama `prompt_eval_count` /
  `eval_count`) and attached to an `inference` observation event.

### Health checks

A background task polls each backend's `health_path` every
`health_check_interval_seconds` (skip with `0`). The current status of every
backend is always available on demand:

```
curl http://127.0.0.1:8011/healthz
```

### Notes & limitations

- The guard **buffers** responses (bounded by `max_body_bytes`) so it can parse
  token usage; streaming responses are therefore delivered in a single shot
  rather than incrementally.
- Hop-by-hop headers are stripped on forward.
- Content inspection is signature/heuristic based — tune
  `detect_*` / `block_on_*` to your tolerance for false positives before
  enabling hard blocking.
