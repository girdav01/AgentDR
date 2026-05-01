from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from ..models import (
    EventRecord,
    utc_now_iso,
    gen_trace_id,
    gen_span_id,
    classify_ai_endpoint,
    classify_messaging_endpoint,
    CLASS_LLM_INFERENCE,
    CLASS_AGENT_ACTION,
    CLASS_PERMISSION_ESCALATION,
    ACTIVITY_CREATE,
    ACTIVITY_EXECUTE,
    STATUS_SUCCESS,
    SEVERITY_MAP,
)


class NetworkMonitor:
    """Monitor network activity for AI API calls.

    Supports two modes:
    - proxy: Uses mitmproxy to intercept HTTPS traffic (requires cert install)
    - fallback: Polls /proc/net or ss for connection info (lower fidelity)
    """

    def __init__(
        self,
        mode: str,
        proxy_host: str,
        proxy_port: int,
        fallback_poll_seconds: int,
        ai_api_endpoints: List[str],
        runtime_dir: Path,
        proxy_events_file: Path,
        emit: Callable[[EventRecord], None],
    ) -> None:
        self.mode = mode
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.fallback_poll_seconds = max(1, fallback_poll_seconds)
        self.ai_api_endpoints = [e.lower() for e in ai_api_endpoints]
        self.runtime_dir = runtime_dir
        self.proxy_events_file = proxy_events_file
        self.emit = emit

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proxy_process: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
        self._seen_lines: int = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        if self.mode == "proxy":
            self._start_proxy()
            target = self._poll_proxy_events
        else:
            target = self._poll_connections_fallback

        self._thread = threading.Thread(target=target, daemon=True, name="network-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._proxy_process:
            try:
                self._proxy_process.terminate()
                self._proxy_process.wait(timeout=3)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    # ---------- Proxy mode ----------

    def _start_proxy(self) -> None:
        addon_path = self.runtime_dir / "mitm_addon.py"
        if not addon_path.exists():
            self.emit(
                EventRecord(
                    timestamp=utc_now_iso(),
                    event_type="monitor_warning",
                    details={"message": f"Addon not found at {addon_path}, falling back"},
                    risk_level="low",
                    source="network_monitor",
                    class_uid=CLASS_AGENT_ACTION,
                    message=f"mitmproxy addon not found at {addon_path}",
                )
            )
            self.mode = "fallback"
            return

        self.proxy_events_file.parent.mkdir(parents=True, exist_ok=True)
        self.proxy_events_file.touch(exist_ok=True)

        cmd = [
            sys.executable, "-m", "mitmproxy",
            "--mode", "regular",
            "--listen-host", self.proxy_host,
            "--listen-port", str(self.proxy_port),
            "-s", str(addon_path),
            "--set", f"events_file={self.proxy_events_file}",
            "--quiet",
        ]

        try:
            self._proxy_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.emit(
                EventRecord(
                    timestamp=utc_now_iso(),
                    event_type="proxy_started",
                    details={"host": self.proxy_host, "port": self.proxy_port},
                    risk_level="low",
                    source="network_monitor",
                    class_uid=CLASS_AGENT_ACTION,
                    message=f"mitmproxy started on {self.proxy_host}:{self.proxy_port}",
                )
            )
        except Exception as exc:
            self.emit(
                EventRecord(
                    timestamp=utc_now_iso(),
                    event_type="monitor_error",
                    details={"error": str(exc), "monitor": "network_proxy"},
                    risk_level="medium",
                    source="network_monitor",
                    class_uid=CLASS_AGENT_ACTION,
                    message=f"Failed to start mitmproxy: {exc}",
                )
            )
            self.mode = "fallback"

    def _poll_proxy_events(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self.proxy_events_file.exists():
                    with self.proxy_events_file.open("r", encoding="utf-8") as f:
                        lines = f.readlines()
                    new_lines = lines[self._seen_lines:]
                    self._seen_lines = len(lines)

                    for raw_line in new_lines:
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        try:
                            record = json.loads(raw_line)
                            self._emit_network_event(record)
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

            self._stop_event.wait(1)

    # ---------- Fallback mode ----------

    def _poll_connections_fallback(self) -> None:
        seen_endpoints: Set[str] = set()

        while not self._stop_event.is_set():
            try:
                connections = self._get_active_connections()
                for conn in connections:
                    host = conn.get("remote_host", "")
                    port = conn.get("remote_port", "")
                    key = f"{host}:{port}"

                    if key in seen_endpoints:
                        continue
                    seen_endpoints.add(key)

                    if self._matches_ai_endpoint(host):
                        self._emit_network_event({
                            "host": host,
                            "port": port,
                            "method": "CONNECT",
                            "url": f"https://{host}/",
                            "status_code": 0,
                        })
            except Exception:
                pass

            self._stop_event.wait(self.fallback_poll_seconds)

    def _get_active_connections(self) -> List[Dict[str, Any]]:
        try:
            result = subprocess.run(
                ["ss", "-tnp"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            connections: List[Dict[str, Any]] = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    peer = parts[4]
                    if ":" in peer:
                        host, port = peer.rsplit(":", 1)
                        connections.append({"remote_host": host, "remote_port": port})
            return connections
        except Exception:
            return []

    def _matches_ai_endpoint(self, host: str) -> bool:
        host_lower = host.lower()
        return any(ep in host_lower for ep in self.ai_api_endpoints)

    # ---------- Shared ----------

    def _emit_network_event(self, record: Dict[str, Any]) -> None:
        host = record.get("host", "unknown")
        ai_info = classify_ai_endpoint(host)
        messaging_platform = classify_messaging_endpoint(host)

        is_ai_api = ai_info is not None or self._matches_ai_endpoint(host)
        is_messaging = messaging_platform is not None

        # Risk assessment: messaging = high (agent acting on comms), AI API = medium
        if is_messaging:
            risk = "high"
        elif is_ai_api:
            risk = "medium"
        else:
            risk = "low"

        # Choose OCSF class based on traffic type
        if ai_info:
            class_uid = CLASS_LLM_INFERENCE
            activity_id = ACTIVITY_EXECUTE
            event_type = "network_request"
            msg = f"AI API request to {host}"
        elif is_messaging:
            class_uid = CLASS_PERMISSION_ESCALATION
            activity_id = ACTIVITY_EXECUTE
            event_type = "messaging_channel_access"
            msg = f"Agent accessing {messaging_platform} via {host}"
        else:
            class_uid = CLASS_AGENT_ACTION
            activity_id = ACTIVITY_CREATE
            event_type = "network_request"
            msg = f"Network request to {host}"

        event = EventRecord(
            timestamp=utc_now_iso(),
            event_type=event_type,
            details={
                "host": host,
                "port": record.get("port"),
                "method": record.get("method"),
                "url": record.get("url"),
                "status_code": record.get("status_code"),
                "is_ai_api": is_ai_api,
                "is_messaging": is_messaging,
                "messaging_platform": messaging_platform,
            },
            risk_level=risk,
            agent_detected="ai_api_call" if is_ai_api else ("messaging_access" if is_messaging else None),
            source="network_monitor",
            # CoSAI OCSF fields
            class_uid=class_uid,
            type_uid=class_uid * 100 + activity_id,
            activity_id=activity_id,
            severity_id=SEVERITY_MAP.get(risk, 1),
            status_id=STATUS_SUCCESS,
            message=msg,
            provider=ai_info["provider"] if ai_info else None,
            model=ai_info["model"] if ai_info else None,
            # Estimate token usage for AI API calls
            token_usage={
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            } if ai_info else None,
            trace_id=gen_trace_id(),
            span_id=gen_span_id(),
        )
        self.emit(event)
