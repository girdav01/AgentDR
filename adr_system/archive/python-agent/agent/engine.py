from __future__ import annotations

import json
import os
import signal
import threading
import time
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, Optional

from .config_manager import ConfigManager
from .detectors import PatternDetector
from .integrity import IntegrityError, RuleIntegrity
from .logging_utils import setup_logger
from .models import (
    EventRecord,
    utc_now_iso,
    gen_trace_id,
    gen_span_id,
    CLASS_AGENT_ACTION,
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    STATUS_SUCCESS,
)
from .monitors import FileMonitor, NetworkMonitor, ProcessMonitor
from .storage import EventPusher, JsonlEventStore


class AgentEngine:
    def __init__(self, root_path: Path, stream_output: bool = True) -> None:
        self.root_path = root_path
        self.stream_output = stream_output

        self.config_manager = ConfigManager(root_path)
        self.config = self.config_manager.load()

        runtime_cfg = self.config["runtime"]
        self.status_file = root_path / runtime_cfg["status_file"]
        log_file = root_path / runtime_cfg["log_file"]
        self.logger = setup_logger("adr-agent", log_file)

        storage_cfg = self.config["storage"]
        self.store = JsonlEventStore(
            events_path=root_path / storage_cfg["events_path"],
            max_bytes=int(storage_cfg["max_bytes"]),
            backup_count=int(storage_cfg["backup_count"]),
        )

        self.pusher = EventPusher(self.config.get("server_push", {}))
        self.detector = PatternDetector(self.config.get("detection", {}))

        self._event_queue: Queue[EventRecord] = Queue()
        self._stop_event = threading.Event()
        self._shutdown_lock = threading.Lock()
        self._shutdown_called = False
        self._writer_thread: Optional[threading.Thread] = None

        self.file_monitor = FileMonitor(
            watch_directories=self.config.get("watch_directories", []),
            recursive=bool(self.config.get("file_monitor", {}).get("recursive", True)),
            ignore_patterns=self.config.get("file_monitor", {}).get("ignore_patterns", []),
            emit=self.emit,
        )

        net_cfg = self.config.get("network_monitor", {})
        self.network_monitor = NetworkMonitor(
            mode=net_cfg.get("mode", "proxy"),
            proxy_host=net_cfg.get("proxy_host", "127.0.0.1"),
            proxy_port=int(net_cfg.get("proxy_port", 8081)),
            fallback_poll_seconds=int(net_cfg.get("fallback_poll_seconds", 3)),
            ai_api_endpoints=net_cfg.get("ai_api_endpoints", []),
            runtime_dir=(root_path / "agent/runtime"),
            proxy_events_file=root_path / runtime_cfg["network_proxy_events_file"],
            emit=self.emit,
        )

        self.process_monitor = ProcessMonitor(
            poll_interval_seconds=int(self.config.get("process_monitor", {}).get("poll_interval_seconds", 2)),
            emit=self.emit,
        )

    def emit(self, event: EventRecord) -> None:
        self._event_queue.put(event)

    def run(self) -> None:
        self.logger.info("Starting CoSAI ADR Agent Engine")

        # ── Startup integrity check + scheduled updater ──
        self._rule_integrity = RuleIntegrity()
        try:
            self._rule_integrity.verify()
            self.logger.info("Community rules integrity check passed")
        except IntegrityError as exc:
            self.logger.warning("Community rules integrity issue at startup: %s", exc)
            self.logger.info("Attempting automatic rule update...")
            result = self._rule_integrity.update()
            self.logger.info("Auto-update result: %s", result.get("status"))

        # Start background 24h updater (default 01:00 UTC)
        update_cfg = self.config.get("rules_update", {})
        update_hour = int(update_cfg.get("hour", 1))
        update_minute = int(update_cfg.get("minute", 0))
        self._rule_integrity.schedule(hour=update_hour, minute=update_minute)

        self._register_signal_handlers()
        self._write_status("running")

        self.pusher.start()
        self._writer_thread = threading.Thread(target=self._event_writer_loop, daemon=True, name="event-writer")
        self._writer_thread.start()

        self.file_monitor.start()
        self.network_monitor.start()
        self.process_monitor.start()

        self.emit(
            EventRecord(
                timestamp=utc_now_iso(),
                event_type="agent_started",
                details={"watch_directories": self.config.get("watch_directories", [])},
                risk_level="low",
                source="engine",
                class_uid=CLASS_AGENT_ACTION,
                type_uid=CLASS_AGENT_ACTION * 100 + ACTIVITY_CREATE,
                activity_id=ACTIVITY_CREATE,
                status_id=STATUS_SUCCESS,
                message="CoSAI ADR Agent Engine started",
                agent_name="ADR Monitor",
                agent_framework="CoSAI",
                trace_id=gen_trace_id(),
                span_id=gen_span_id(),
            )
        )

        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        with self._shutdown_lock:
            if self._shutdown_called:
                return
            self._shutdown_called = True

        self._stop_event.set()
        self.logger.info("Shutting down CoSAI ADR Agent Engine")

        self.file_monitor.stop()
        self.network_monitor.stop()
        self.process_monitor.stop()

        self.emit(
            EventRecord(
                timestamp=utc_now_iso(),
                event_type="agent_stopped",
                details={},
                risk_level="low",
                source="engine",
                class_uid=CLASS_AGENT_ACTION,
                type_uid=CLASS_AGENT_ACTION * 100 + ACTIVITY_DELETE,
                activity_id=ACTIVITY_DELETE,
                status_id=STATUS_SUCCESS,
                message="CoSAI ADR Agent Engine stopped",
                agent_name="ADR Monitor",
                agent_framework="CoSAI",
                trace_id=gen_trace_id(),
                span_id=gen_span_id(),
            )
        )

        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=4)

        self.pusher.stop()
        self._write_status("stopped")

    def _event_writer_loop(self) -> None:
        while not self._stop_event.is_set() or not self._event_queue.empty():
            try:
                event = self._event_queue.get(timeout=0.5)
            except Empty:
                continue

            self._persist_and_stream(event)
            alerts = self.detector.analyze(event)
            for alert in alerts:
                self._persist_and_stream(alert)

    def _persist_and_stream(self, event: EventRecord) -> None:
        self.store.write_event(event)
        self.pusher.enqueue(event)
        if self.stream_output:
            print(self._format_event(event), flush=True)

    @staticmethod
    def _format_event(event: EventRecord) -> str:
        return (
            f"[{event.timestamp}] {event.risk_level.upper():8} "
            f"{event.event_type:32} | {json.dumps(event.details, ensure_ascii=False)}"
        )

    def _register_signal_handlers(self) -> None:
        def _handler(*_: object) -> None:
            self._stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                continue

    def _write_status(self, status: str) -> None:
        payload: Dict[str, Any] = {
            "status": status,
            "timestamp": utc_now_iso(),
            "pid": os.getpid(),
        }
        self.status_file.parent.mkdir(parents=True, exist_ok=True)
        with self.status_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
