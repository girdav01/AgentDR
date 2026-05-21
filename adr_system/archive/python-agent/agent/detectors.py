from __future__ import annotations

import collections
import time
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Tuple

from .models import (
    EventRecord,
    utc_now_iso,
    gen_trace_id,
    gen_span_id,
    CLASS_AGENT_ACTION,
    CLASS_TOOL_EXECUTION,
    CLASS_DATA_EXFILTRATION,
    CLASS_COST_ANOMALY,
    CLASS_MCP_OPERATION,
    CLASS_PERMISSION_ESCALATION,
    ACTIVITY_DETECT,
    STATUS_SUCCESS,
    SEVERITY_MAP,
    DETECTION_RULES,
    MESSAGING_ENDPOINTS,
    AGENT_SKILL_PATHS,
)


# Credential-sensitive file patterns
CREDENTIAL_PATTERNS = (
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_ed25519", "id_ecdsa", "known_hosts", "authorized_keys",
    ".aws/credentials", ".aws/config",
    ".gcloud/credentials.json", ".config/gcloud",
    ".npmrc", ".pypirc",
    "secrets.json", "service-account.json", "keyfile.json",
)


class PatternDetector:
    def __init__(self, detection_config: Dict[str, Any]) -> None:
        self.cfg = detection_config
        self.file_mod_times: Deque[Tuple[float, str]] = collections.deque()
        self.api_call_times: Deque[float] = collections.deque()
        self.deleted_sizes: Deque[Tuple[float, int]] = collections.deque()
        # New trackers for OpenClaw / general-agent rules
        self.skill_file_events: Deque[Tuple[float, str]] = collections.deque()
        self.messaging_events: Deque[Tuple[float, str]] = collections.deque()
        self.shell_exec_events: Deque[Tuple[float, str]] = collections.deque()
        self.credential_access_events: Deque[Tuple[float, str]] = collections.deque()
        self.ai_api_hosts: Deque[Tuple[float, str]] = collections.deque()
        self.messaging_hosts: Deque[Tuple[float, str]] = collections.deque()

    def analyze(self, event: EventRecord) -> List[EventRecord]:
        alerts: List[EventRecord] = []
        now = time.time()

        if event.event_type == "file_modified":
            alerts.extend(self._check_rapid_modifications(event, now))
        elif event.event_type == "network_request":
            alerts.extend(self._check_api_volume(event, now))
        elif event.event_type == "file_deleted":
            alerts.extend(self._check_large_deletions(event, now))

        # ── New OpenClaw / general-agent detections ──
        # DET-015: Malicious skill/plugin loaded
        if event.event_type in ("file_created", "file_modified") and event.details.get("is_skill_path"):
            alerts.extend(self._check_skill_plugin(event, now))

        # DET-016: Unauthorized messaging channel
        if event.event_type == "messaging_channel_access":
            alerts.extend(self._check_messaging_channel(event, now))

        # DET-017: Shell command execution
        if event.event_type == "process_started" and self._is_shell_process(event):
            alerts.extend(self._check_shell_execution(event, now))

        # DET-018: Credential access
        if event.event_type in ("file_created", "file_modified", "file_read") and self._is_credential_file(event):
            alerts.extend(self._check_credential_access(event, now))

        # DET-019: Cross-platform data relay (AI API + messaging in same window)
        if event.event_type == "network_request":
            host = event.details.get("host", "")
            if event.details.get("ai_provider"):
                self.ai_api_hosts.append((now, host))
            if event.details.get("messaging_platform"):
                self.messaging_hosts.append((now, host))
            alerts.extend(self._check_cross_platform_relay(event, now))

        # DET-020: Unvetted skill installation (new file created in skill path)
        if event.event_type == "file_created" and event.details.get("is_skill_path"):
            alerts.extend(self._check_unvetted_skill(event, now))

        return alerts

    def _make_alert(
        self,
        rule_id: str,
        event_type: str,
        details: Dict[str, Any],
        risk_level: str,
        agent_detected: Optional[str] = None,
        parent_trace_id: Optional[str] = None,
    ) -> EventRecord:
        """Create a CoSAI-compliant detection alert."""
        rule = DETECTION_RULES.get(rule_id, {})
        class_uid = rule.get("class_uid", CLASS_AGENT_ACTION)

        return EventRecord(
            timestamp=utc_now_iso(),
            event_type=event_type,
            details={
                **details,
                "rule_id": rule_id,
                "rule_name": rule.get("name", "Unknown"),
                "owasp_category": rule.get("owasp", "LLM00"),
            },
            risk_level=risk_level,
            agent_detected=agent_detected,
            source="detector",
            class_uid=class_uid,
            type_uid=class_uid * 100 + ACTIVITY_DETECT,
            activity_id=ACTIVITY_DETECT,
            severity_id=SEVERITY_MAP.get(risk_level, 3),
            status_id=STATUS_SUCCESS,
            message=f"[{rule_id}] {rule.get('name', event_type)}",
            security_finding={
                "rule_id": rule_id,
                "title": rule.get("name", "Unknown"),
                "severity": risk_level,
                "owasp_llm": rule.get("owasp", "LLM00"),
            },
            compliance={
                "frameworks": ["OWASP-LLM-Top10", "NIST-AI-RMF"],
                "mappings": {"OWASP-LLM-Top10": rule.get("owasp", "LLM00")},
            },
            trace_id=parent_trace_id or gen_trace_id(),
            span_id=gen_span_id(),
        )

    def _check_rapid_modifications(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("rapid_file_modifications", {})
        if not rule.get("enabled", True):
            return []

        window = int(rule.get("window_seconds", 60))
        threshold = int(rule.get("threshold_count", 10))

        self.file_mod_times.append((now, event.details.get("path", "unknown")))
        while self.file_mod_times and now - self.file_mod_times[0][0] > window:
            self.file_mod_times.popleft()

        unique_files = {path for _, path in self.file_mod_times}
        count = len(unique_files)

        if count <= threshold:
            return []

        risk = "high" if count <= threshold * 2 else "critical"
        return [
            self._make_alert(
                rule_id="AITF-DET-009",
                event_type="alert_rapid_file_modifications",
                details={
                    "count": count,
                    "window_seconds": window,
                    "threshold": threshold,
                },
                risk_level=risk,
                agent_detected="possible_agent_automation",
                parent_trace_id=event.trace_id,
            )
        ]

    def _check_api_volume(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("unusual_api_call_volume", {})
        if not rule.get("enabled", True):
            return []

        window = int(rule.get("window_seconds", 60))
        threshold = int(rule.get("threshold_count", 40))

        self.api_call_times.append(now)
        while self.api_call_times and now - self.api_call_times[0] > window:
            self.api_call_times.popleft()

        count = len(self.api_call_times)
        if count <= threshold:
            return []

        risk = "medium" if count <= threshold * 2 else "high"
        return [
            self._make_alert(
                rule_id="AITF-DET-012",
                event_type="alert_unusual_api_call_volume",
                details={
                    "count": count,
                    "window_seconds": window,
                    "threshold": threshold,
                    "endpoint": event.details.get("host"),
                },
                risk_level=risk,
                agent_detected="possible_agent_networking",
                parent_trace_id=event.trace_id,
            )
        ]

    def _check_large_deletions(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("large_file_deletions", {})
        if not rule.get("enabled", True):
            return []

        size_bytes = int(event.details.get("size_bytes", 0) or 0)
        single_mb = float(rule.get("single_file_mb", 25))
        total_mb = float(rule.get("window_total_mb", 200))
        window = int(rule.get("window_seconds", 300))

        alerts: List[EventRecord] = []

        self.deleted_sizes.append((now, size_bytes))
        while self.deleted_sizes and now - self.deleted_sizes[0][0] > window:
            self.deleted_sizes.popleft()

        window_bytes = sum(size for _, size in self.deleted_sizes)

        if size_bytes >= single_mb * 1024 * 1024:
            alerts.append(
                self._make_alert(
                    rule_id="AITF-DET-010",
                    event_type="alert_large_file_deleted",
                    details={
                        "path": event.details.get("path"),
                        "size_bytes": size_bytes,
                        "single_file_mb_threshold": single_mb,
                    },
                    risk_level="high",
                    agent_detected="possible_agent_cleanup",
                    parent_trace_id=event.trace_id,
                )
            )

        if window_bytes >= total_mb * 1024 * 1024:
            alerts.append(
                self._make_alert(
                    rule_id="AITF-DET-010",
                    event_type="alert_bulk_file_deletions",
                    details={
                        "window_seconds": window,
                        "total_deleted_bytes": window_bytes,
                        "window_total_mb_threshold": total_mb,
                    },
                    risk_level="critical",
                    agent_detected="possible_destructive_behavior",
                    parent_trace_id=event.trace_id,
                )
            )

        return alerts

    # ── DET-015: Malicious Skill/Plugin Loaded ──
    def _check_skill_plugin(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("malicious_skill_plugin", {})
        if not rule.get("enabled", True):
            return []

        window = int(rule.get("window_seconds", 300))
        threshold = int(rule.get("threshold_count", 5))

        path = event.details.get("path", "")
        self.skill_file_events.append((now, path))
        while self.skill_file_events and now - self.skill_file_events[0][0] > window:
            self.skill_file_events.popleft()

        # Suspicious patterns: executable files, obfuscated names, many files at once
        suspicious_exts = (".py", ".js", ".sh", ".bat", ".exe", ".dll", ".so")
        is_executable = any(path.endswith(ext) for ext in suspicious_exts)
        burst = len(self.skill_file_events) >= threshold

        if not (is_executable or burst):
            return []

        risk = "critical" if burst else "high"
        return [
            self._make_alert(
                rule_id="AITF-DET-015",
                event_type="alert_malicious_skill_plugin",
                details={
                    "path": path,
                    "is_executable": is_executable,
                    "skill_files_in_window": len(self.skill_file_events),
                    "window_seconds": window,
                },
                risk_level=risk,
                agent_detected="openclaw_skill_install",
                parent_trace_id=event.trace_id,
            )
        ]

    # ── DET-016: Unauthorized Messaging Channel Access ──
    def _check_messaging_channel(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("unauthorized_messaging", {})
        if not rule.get("enabled", True):
            return []

        platform = event.details.get("messaging_platform", "unknown")
        host = event.details.get("host", "")
        self.messaging_events.append((now, platform))

        return [
            self._make_alert(
                rule_id="AITF-DET-016",
                event_type="alert_unauthorized_messaging",
                details={
                    "platform": platform,
                    "host": host,
                    "endpoint": event.details.get("path", ""),
                },
                risk_level="high",
                agent_detected="messaging_agent",
                parent_trace_id=event.trace_id,
            )
        ]

    # ── DET-017: Shell Command Execution by Agent ──
    def _check_shell_execution(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("shell_command_execution", {})
        if not rule.get("enabled", True):
            return []

        window = int(rule.get("window_seconds", 60))
        threshold = int(rule.get("threshold_count", 5))

        cmd = event.details.get("command", event.details.get("name", ""))
        self.shell_exec_events.append((now, cmd))
        while self.shell_exec_events and now - self.shell_exec_events[0][0] > window:
            self.shell_exec_events.popleft()

        count = len(self.shell_exec_events)
        if count < 1:
            return []

        risk = "critical" if count >= threshold else "high"
        return [
            self._make_alert(
                rule_id="AITF-DET-017",
                event_type="alert_shell_command_execution",
                details={
                    "command": cmd,
                    "shell_commands_in_window": count,
                    "window_seconds": window,
                    "parent_pid": event.details.get("ppid"),
                },
                risk_level=risk,
                agent_detected="shell_executing_agent",
                parent_trace_id=event.trace_id,
            )
        ]

    # ── DET-018: Credential / Secret Access ──
    def _check_credential_access(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("credential_access", {})
        if not rule.get("enabled", True):
            return []

        path = event.details.get("path", "")
        self.credential_access_events.append((now, path))

        return [
            self._make_alert(
                rule_id="AITF-DET-018",
                event_type="alert_credential_access",
                details={
                    "path": path,
                    "event_type": event.event_type,
                },
                risk_level="critical",
                agent_detected="credential_harvesting",
                parent_trace_id=event.trace_id,
            )
        ]

    # ── DET-019: Cross-Platform Data Relay ──
    def _check_cross_platform_relay(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("cross_platform_relay", {})
        if not rule.get("enabled", True):
            return []

        window = int(rule.get("window_seconds", 300))

        # Clean old entries
        while self.ai_api_hosts and now - self.ai_api_hosts[0][0] > window:
            self.ai_api_hosts.popleft()
        while self.messaging_hosts and now - self.messaging_hosts[0][0] > window:
            self.messaging_hosts.popleft()

        # Fire if both AI API and messaging traffic in same window
        if not self.ai_api_hosts or not self.messaging_hosts:
            return []

        ai_hosts = {h for _, h in self.ai_api_hosts}
        msg_hosts = {h for _, h in self.messaging_hosts}

        return [
            self._make_alert(
                rule_id="AITF-DET-019",
                event_type="alert_cross_platform_relay",
                details={
                    "ai_api_hosts": list(ai_hosts),
                    "messaging_hosts": list(msg_hosts),
                    "window_seconds": window,
                },
                risk_level="critical",
                agent_detected="data_relay_agent",
                parent_trace_id=event.trace_id,
            )
        ]

    # ── DET-020: Unvetted Skill Installation ──
    def _check_unvetted_skill(self, event: EventRecord, now: float) -> List[EventRecord]:
        rule = self.cfg.get("unvetted_skill_install", {})
        if not rule.get("enabled", True):
            return []

        path = event.details.get("path", "")
        return [
            self._make_alert(
                rule_id="AITF-DET-020",
                event_type="alert_unvetted_skill_installation",
                details={
                    "path": path,
                    "size_bytes": event.details.get("size_bytes", 0),
                },
                risk_level="high",
                agent_detected="skill_installer",
                parent_trace_id=event.trace_id,
            )
        ]

    # ── Helper methods ──
    @staticmethod
    def _is_shell_process(event: EventRecord) -> bool:
        """Check if event represents a shell command spawned by an agent."""
        name = event.details.get("name", "").lower()
        cmd = event.details.get("command", "").lower()
        shell_names = ("bash", "sh", "zsh", "cmd", "powershell", "pwsh", "fish")
        return name in shell_names or any(s in cmd for s in shell_names)

    @staticmethod
    def _is_credential_file(event: EventRecord) -> bool:
        """Check if the file path matches known credential/secret patterns."""
        path = event.details.get("path", "").lower()
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.lower() in path:
                return True
        return False
