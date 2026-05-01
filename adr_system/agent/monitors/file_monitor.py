from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Dict, List, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..models import (
    EventRecord,
    utc_now_iso,
    gen_trace_id,
    gen_span_id,
    CLASS_TOOL_EXECUTION,
    CLASS_MCP_OPERATION,
    ACTIVITY_CREATE,
    ACTIVITY_UPDATE,
    ACTIVITY_DELETE,
    STATUS_SUCCESS,
    SEVERITY_MAP,
    is_skill_path,
)


class _WatchHandler(FileSystemEventHandler):
    def __init__(
        self,
        emit: Callable[[EventRecord], None],
        ignore_patterns: List[str],
        size_cache: Dict[str, int],
    ) -> None:
        self.emit = emit
        self.ignore_patterns = ignore_patterns
        self.size_cache = size_cache
        super().__init__()

    def dispatch(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if self._is_ignored(event.src_path):
            return
        super().dispatch(event)

    def _skill_context(self, path: str) -> dict:
        """Return elevated risk/class if path is inside an agent skill directory."""
        if is_skill_path(path):
            return {
                "risk_level": "high",
                "class_uid": CLASS_MCP_OPERATION,
                "is_skill_path": True,
            }
        return {
            "risk_level": "low",
            "class_uid": CLASS_TOOL_EXECUTION,
            "is_skill_path": False,
        }

    def on_created(self, event: FileSystemEvent) -> None:
        size = self._safe_size(event.src_path)
        self.size_cache[event.src_path] = size
        ctx = self._skill_context(event.src_path)
        cls = ctx["class_uid"]
        risk = ctx["risk_level"]
        msg = f"File created: {Path(event.src_path).name}"
        if ctx["is_skill_path"]:
            msg = f"[SKILL] {msg} — potential plugin installation"
        self.emit(
            EventRecord(
                timestamp=utc_now_iso(),
                event_type="file_created",
                details={"path": event.src_path, "size_bytes": size, "is_skill_path": ctx["is_skill_path"]},
                risk_level=risk,
                source="file_monitor",
                class_uid=cls,
                type_uid=cls * 100 + ACTIVITY_CREATE,
                activity_id=ACTIVITY_CREATE,
                severity_id=SEVERITY_MAP.get(risk, 1),
                status_id=STATUS_SUCCESS,
                message=msg,
                tool_name="filesystem",
                actor={"process": "file_monitor"},
                security_finding={
                    "title": "Skill/Plugin File Created",
                    "severity": risk,
                    "description": f"New file in agent skill directory: {event.src_path}",
                } if ctx["is_skill_path"] else None,
                trace_id=gen_trace_id(),
                span_id=gen_span_id(),
            )
        )

    def on_modified(self, event: FileSystemEvent) -> None:
        size = self._safe_size(event.src_path)
        self.size_cache[event.src_path] = size
        ctx = self._skill_context(event.src_path)
        cls = ctx["class_uid"]
        risk = ctx["risk_level"] if ctx["is_skill_path"] else "low"
        msg = f"File modified: {Path(event.src_path).name}"
        if ctx["is_skill_path"]:
            msg = f"[SKILL] {msg} — skill code modified"
        self.emit(
            EventRecord(
                timestamp=utc_now_iso(),
                event_type="file_modified",
                details={"path": event.src_path, "size_bytes": size, "is_skill_path": ctx["is_skill_path"]},
                risk_level=risk,
                source="file_monitor",
                class_uid=cls,
                type_uid=cls * 100 + ACTIVITY_UPDATE,
                activity_id=ACTIVITY_UPDATE,
                severity_id=SEVERITY_MAP.get(risk, 1),
                status_id=STATUS_SUCCESS,
                message=msg,
                tool_name="filesystem",
                security_finding={
                    "title": "Skill/Plugin File Modified",
                    "severity": risk,
                    "description": f"Modified file in agent skill directory: {event.src_path}",
                } if ctx["is_skill_path"] else None,
                trace_id=gen_trace_id(),
                span_id=gen_span_id(),
            )
        )

    def on_deleted(self, event: FileSystemEvent) -> None:
        size = self.size_cache.pop(event.src_path, 0)
        risk = "high" if size >= 25 * 1024 * 1024 else "medium"
        self.emit(
            EventRecord(
                timestamp=utc_now_iso(),
                event_type="file_deleted",
                details={"path": event.src_path, "size_bytes": size},
                risk_level=risk,
                source="file_monitor",
                class_uid=CLASS_TOOL_EXECUTION,
                type_uid=CLASS_TOOL_EXECUTION * 100 + ACTIVITY_DELETE,
                activity_id=ACTIVITY_DELETE,
                severity_id=SEVERITY_MAP.get(risk, 3),
                status_id=STATUS_SUCCESS,
                message=f"File deleted: {Path(event.src_path).name} ({size} bytes)",
                tool_name="filesystem",
                security_finding={
                    "title": "File Deletion",
                    "severity": risk,
                    "description": f"File {event.src_path} deleted ({size} bytes)",
                } if risk != "low" else None,
                trace_id=gen_trace_id(),
                span_id=gen_span_id(),
            )
        )

    def on_moved(self, event: FileSystemEvent) -> None:
        src_size = self.size_cache.pop(event.src_path, 0)
        dst_size = self._safe_size(event.dest_path)
        self.size_cache[event.dest_path] = dst_size
        self.emit(
            EventRecord(
                timestamp=utc_now_iso(),
                event_type="file_moved",
                details={
                    "src_path": event.src_path,
                    "dest_path": event.dest_path,
                    "size_bytes": src_size or dst_size,
                },
                risk_level="low",
                source="file_monitor",
                class_uid=CLASS_TOOL_EXECUTION,
                type_uid=CLASS_TOOL_EXECUTION * 100 + ACTIVITY_UPDATE,
                activity_id=ACTIVITY_UPDATE,
                status_id=STATUS_SUCCESS,
                message=f"File moved: {Path(event.src_path).name} -> {Path(event.dest_path).name}",
                tool_name="filesystem",
                trace_id=gen_trace_id(),
                span_id=gen_span_id(),
            )
        )

    def _is_ignored(self, path: str) -> bool:
        filename = Path(path).name
        for pattern in self.ignore_patterns:
            if Path(filename).match(pattern):
                return True
        return False

    @staticmethod
    def _safe_size(path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0


class FileMonitor:
    def __init__(
        self,
        watch_directories: List[str],
        recursive: bool,
        ignore_patterns: List[str],
        emit: Callable[[EventRecord], None],
    ) -> None:
        self.watch_directories = watch_directories
        self.recursive = recursive
        self.ignore_patterns = ignore_patterns
        self.emit = emit

        self._observer: Optional[Observer] = None
        self._size_cache: Dict[str, int] = {}

    def start(self) -> None:
        if self._observer:
            return

        self._observer = Observer()
        handler = _WatchHandler(self.emit, self.ignore_patterns, self._size_cache)

        for directory in self.watch_directories:
            path_obj = Path(directory).expanduser().resolve()
            if not path_obj.exists() or not path_obj.is_dir():
                self.emit(
                    EventRecord(
                        timestamp=utc_now_iso(),
                        event_type="monitor_warning",
                        details={"message": f"Watch directory not found: {path_obj}"},
                        risk_level="low",
                        source="file_monitor",
                        class_uid=CLASS_TOOL_EXECUTION,
                        message=f"Watch directory not found: {path_obj}",
                    )
                )
                continue
            self._observer.schedule(handler, str(path_obj), recursive=self.recursive)

        self._observer.start()

    def stop(self) -> None:
        if not self._observer:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = None
