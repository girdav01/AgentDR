from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Dict, Iterable, List

from .models import EventRecord


class JsonlEventStore:
    def __init__(self, events_path: Path, max_bytes: int, backup_count: int) -> None:
        self.events_path = events_path
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()
        self.events_path.parent.mkdir(parents=True, exist_ok=True)
        self.events_path.touch(exist_ok=True)

    def write_event(self, event: EventRecord) -> None:
        row = json.dumps(event.to_dict(), ensure_ascii=False)
        with self._lock:
            self._rotate_if_needed(len(row.encode("utf-8")) + 1)
            with self.events_path.open("a", encoding="utf-8") as f:
                f.write(row + "\n")

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        if not self.events_path.exists():
            return
        current = self.events_path.stat().st_size
        if current + incoming_bytes <= self.max_bytes:
            return

        for idx in range(self.backup_count - 1, 0, -1):
            src = self.events_path.with_suffix(self.events_path.suffix + f".{idx}")
            dst = self.events_path.with_suffix(self.events_path.suffix + f".{idx + 1}")
            if src.exists():
                src.replace(dst)

        first_backup = self.events_path.with_suffix(self.events_path.suffix + ".1")
        self.events_path.replace(first_backup)
        self.events_path.touch(exist_ok=True)

    def iter_events(self) -> Iterable[Dict[str, Any]]:
        files: List[Path] = [
            self.events_path,
            *sorted(self.events_path.parent.glob(self.events_path.name + ".*")),
        ]
        for file_path in files:
            if not file_path.exists() or not file_path.is_file():
                continue
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    def compute_stats(self) -> Dict[str, Any]:
        total = 0
        by_type: Counter[str] = Counter()
        by_risk: Counter[str] = Counter()
        by_class: Counter[int] = Counter()
        by_provider: Counter[str] = Counter()
        by_model: Counter[str] = Counter()

        for event in self.iter_events():
            total += 1
            by_type[event.get("event_type", "unknown")] += 1
            by_risk[event.get("risk_level", "unknown")] += 1
            if event.get("class_uid"):
                by_class[event["class_uid"]] += 1
            if event.get("provider"):
                by_provider[event["provider"]] += 1
            if event.get("model"):
                by_model[event["model"]] += 1

        return {
            "total_events": total,
            "by_event_type": dict(by_type),
            "by_risk_level": dict(by_risk),
            "by_ocsf_class": {str(k): v for k, v in by_class.items()},
            "by_provider": dict(by_provider),
            "by_model": dict(by_model),
        }


class EventPusher:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.enabled = bool(config.get("enabled", False))
        self.endpoint = config.get("endpoint", "")
        self.api_key = config.get("api_key", "")
        self.timeout_seconds = int(config.get("timeout_seconds", 5))
        self.batch_size = int(config.get("batch_size", 10))
        self.flush_interval_seconds = int(config.get("flush_interval_seconds", 5))

        self._queue: Queue[Dict[str, Any]] = Queue()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.enabled or not self.endpoint:
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="event-pusher")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def enqueue(self, event: EventRecord) -> None:
        if not self.enabled or not self.endpoint:
            return
        self._queue.put(event.to_dict())

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            batch: List[Dict[str, Any]] = []
            start = time.monotonic()
            while len(batch) < self.batch_size:
                timeout = max(0.05, self.flush_interval_seconds - (time.monotonic() - start))
                try:
                    item = self._queue.get(timeout=timeout)
                    batch.append(item)
                except Empty:
                    break

            if not batch:
                continue

            try:
                self._send(batch)
            except Exception:
                time.sleep(1)
                for item in batch:
                    self._queue.put(item)

    def _send(self, batch: List[Dict[str, Any]]) -> None:
        payload = json.dumps({"events": batch}).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}" if self.api_key else "",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                if resp.status >= 300:
                    raise RuntimeError(f"Push failed with status {resp.status}")
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Push failed: {exc}") from exc
