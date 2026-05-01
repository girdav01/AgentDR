from __future__ import annotations

import threading
import time
from typing import Callable, Dict, Optional, Set

import psutil

from ..models import (
    EventRecord,
    utc_now_iso,
    gen_trace_id,
    gen_span_id,
    identify_agent_process,
    CLASS_AGENT_ACTION,
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    STATUS_SUCCESS,
    SEVERITY_MAP,
)


class ProcessMonitor:
    def __init__(self, poll_interval_seconds: int, emit: Callable[[EventRecord], None]) -> None:
        self.poll_interval_seconds = max(1, poll_interval_seconds)
        self.emit = emit
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known_pids: Set[int] = set()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._known_pids = {proc.pid for proc in psutil.process_iter(attrs=[])}
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="process-monitor")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                current_pids: Set[int] = set()
                for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "username"]):
                    current_pids.add(proc.info["pid"])
                    if proc.info["pid"] not in self._known_pids:
                        details: Dict[str, object] = {
                            "pid": proc.info.get("pid"),
                            "name": proc.info.get("name"),
                            "exe": proc.info.get("exe"),
                            "cmdline": proc.info.get("cmdline") or [],
                            "username": proc.info.get("username"),
                        }

                        # CoSAI: identify AI agent from process signature
                        agent_info = identify_agent_process(details)
                        is_agent = agent_info is not None
                        risk = "medium" if is_agent else "low"

                        self.emit(
                            EventRecord(
                                timestamp=utc_now_iso(),
                                event_type="process_started",
                                details=details,
                                risk_level=risk,
                                agent_detected=agent_info["name"] if agent_info else None,
                                source="process_monitor",
                                # CoSAI OCSF fields
                                class_uid=CLASS_AGENT_ACTION,
                                type_uid=CLASS_AGENT_ACTION * 100 + ACTIVITY_CREATE,
                                activity_id=ACTIVITY_CREATE,
                                severity_id=SEVERITY_MAP.get(risk, 1),
                                status_id=STATUS_SUCCESS,
                                message=f"Process started: {details.get('name', 'unknown')}",
                                agent_name=agent_info["name"] if agent_info else None,
                                agent_framework=agent_info["framework"] if agent_info else None,
                                actor={"user": str(details.get("username", "unknown")), "pid": details.get("pid")},
                                trace_id=gen_trace_id(),
                                span_id=gen_span_id(),
                            )
                        )

                terminated = self._known_pids - current_pids
                for pid in terminated:
                    self.emit(
                        EventRecord(
                            timestamp=utc_now_iso(),
                            event_type="process_ended",
                            details={"pid": pid},
                            risk_level="low",
                            source="process_monitor",
                            class_uid=CLASS_AGENT_ACTION,
                            type_uid=CLASS_AGENT_ACTION * 100 + ACTIVITY_DELETE,
                            activity_id=ACTIVITY_DELETE,
                            message=f"Process ended: PID {pid}",
                            trace_id=gen_trace_id(),
                            span_id=gen_span_id(),
                        )
                    )

                self._known_pids = current_pids
            except Exception as exc:
                self.emit(
                    EventRecord(
                        timestamp=utc_now_iso(),
                        event_type="monitor_error",
                        details={"monitor": "process", "error": str(exc)},
                        risk_level="medium",
                        source="process_monitor",
                        class_uid=CLASS_AGENT_ACTION,
                        message=f"Process monitor error: {exc}",
                    )
                )
            self._stop_event.wait(self.poll_interval_seconds)
