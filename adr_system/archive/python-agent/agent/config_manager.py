from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_CONFIG: Dict[str, Any] = {
    "watch_directories": [],
    "file_monitor": {
        "recursive": True,
        "ignore_patterns": ["*.tmp", "*.swp", "*.DS_Store"],
    },
    "network_monitor": {
        "mode": "proxy",  
        "proxy_host": "127.0.0.1",
        "proxy_port": 8081,
        "fallback_poll_seconds": 3,
        "ai_api_endpoints": [
            "api.openai.com",
            "api.anthropic.com",
            "api.cohere.ai",
            "generativelanguage.googleapis.com",
            "api.mistral.ai",
        ],
    },
    "process_monitor": {
        "poll_interval_seconds": 2,
    },
    "detection": {
        "rapid_file_modifications": {
            "enabled": True,
            "threshold_count": 10,
            "window_seconds": 60,
        },
        "unusual_api_call_volume": {
            "enabled": True,
            "threshold_count": 40,
            "window_seconds": 60,
        },
        "large_file_deletions": {
            "enabled": True,
            "single_file_mb": 25,
            "window_total_mb": 200,
            "window_seconds": 300,
        },
    },
    "storage": {
        "events_path": "agent/logs/events.jsonl",
        "max_bytes": 5_000_000,
        "backup_count": 7,
    },
    "server_push": {
        "enabled": False,
        "endpoint": "",
        "api_key": "",
        "timeout_seconds": 5,
        "batch_size": 10,
        "flush_interval_seconds": 5,
    },
    "runtime": {
        "pid_file": "agent/runtime/adr_agent.pid",
        "status_file": "agent/runtime/status.json",
        "network_proxy_events_file": "agent/runtime/network_proxy_events.jsonl",
        "log_file": "agent/logs/agent_runtime.log",
    },
}


class ConfigManager:
    def __init__(self, root_path: Path) -> None:
        self.root_path = root_path
        self.config_path = root_path / "config.json"

    def load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            self.save(DEFAULT_CONFIG)
            return json.loads(json.dumps(DEFAULT_CONFIG))
        with self.config_path.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        merged = self._deep_merge(json.loads(json.dumps(DEFAULT_CONFIG)), raw)
        return merged

    def save(self, config: Dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with self.config_path.open("w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    def add_watch_directory(self, directory: str) -> Dict[str, Any]:
        cfg = self.load()
        watch_dirs: List[str] = cfg.get("watch_directories", [])
        if directory not in watch_dirs:
            watch_dirs.append(directory)
        cfg["watch_directories"] = watch_dirs
        self.save(cfg)
        return cfg

    def remove_watch_directory(self, directory: str) -> Dict[str, Any]:
        cfg = self.load()
        watch_dirs: List[str] = cfg.get("watch_directories", [])
        cfg["watch_directories"] = [d for d in watch_dirs if d != directory]
        self.save(cfg)
        return cfg

    @staticmethod
    def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = ConfigManager._deep_merge(base[key], value)
            else:
                base[key] = value
        return base
