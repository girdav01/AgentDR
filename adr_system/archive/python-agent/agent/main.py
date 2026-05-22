from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from .config_manager import ConfigManager
from .engine import AgentEngine
from .integrity import RuleIntegrity
from .service import daemon_status, start_daemon, stop_daemon
from .storage import JsonlEventStore


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_runtime_paths(cfg: Dict[str, Any], root: Path) -> Dict[str, Path]:
    runtime = cfg.get("runtime", {})
    return {
        "pid_file": root / runtime.get("pid_file", "agent/runtime/adr_agent.pid"),
        "runtime_log": root / runtime.get("log_file", "agent/logs/agent_runtime.log"),
        "events_path": root / cfg.get("storage", {}).get("events_path", "agent/logs/events.jsonl"),
    }


def command_start(args: argparse.Namespace) -> None:
    root = project_root()
    cfg = ConfigManager(root).load()
    paths = _load_runtime_paths(cfg, root)

    if args.daemon:
        result = start_daemon(root, paths["pid_file"], paths["runtime_log"])
        print(result["message"])
        return

    engine = AgentEngine(root_path=root, stream_output=not args.no_stream)
    engine.run()


def command_run(args: argparse.Namespace) -> None:
    root = project_root()
    engine = AgentEngine(root_path=root, stream_output=not args.no_stream)
    engine.run()


def command_stop(_: argparse.Namespace) -> None:
    root = project_root()
    cfg = ConfigManager(root).load()
    paths = _load_runtime_paths(cfg, root)
    result = stop_daemon(paths["pid_file"])
    print(result["message"])


def command_status(_: argparse.Namespace) -> None:
    root = project_root()
    cfg = ConfigManager(root).load()
    paths = _load_runtime_paths(cfg, root)
    status = daemon_status(paths["pid_file"])
    print(json.dumps(status, indent=2, default=str))


def command_stats(_: argparse.Namespace) -> None:
    root = project_root()
    cfg = ConfigManager(root).load()
    events_path = root / cfg.get("storage", {}).get("events_path", "agent/logs/events.jsonl")
    store = JsonlEventStore(
        events_path=events_path,
        max_bytes=int(cfg.get("storage", {}).get("max_bytes", 5_000_000)),
        backup_count=int(cfg.get("storage", {}).get("backup_count", 7)),
    )
    stats = store.compute_stats()
    print(json.dumps(stats, indent=2))


def _set_nested(config: Dict[str, Any], dot_key: str, value: Any) -> Dict[str, Any]:
    parts = dot_key.split(".")
    target = config
    for key in parts[:-1]:
        if key not in target or not isinstance(target[key], dict):
            target[key] = {}
        target = target[key]
    target[parts[-1]] = value
    return config


def _json_decode(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def command_config(args: argparse.Namespace) -> None:
    root = project_root()
    manager = ConfigManager(root)

    if args.config_action == "show":
        print(json.dumps(manager.load(), indent=2))
        return

    if args.config_action == "add-watch":
        path = str(Path(args.path).expanduser())
        cfg = manager.add_watch_directory(path)
        print(f"Added watch directory: {path}")
        print(json.dumps(cfg.get("watch_directories", []), indent=2))
        return

    if args.config_action == "remove-watch":
        path = str(Path(args.path).expanduser())
        cfg = manager.remove_watch_directory(path)
        print(f"Removed watch directory: {path}")
        print(json.dumps(cfg.get("watch_directories", []), indent=2))
        return

    if args.config_action == "set":
        cfg = manager.load()
        value = _json_decode(args.value)
        cfg = _set_nested(cfg, args.key, value)
        manager.save(cfg)
        print(f"Updated {args.key}")
        return


def command_update(args: argparse.Namespace) -> None:
    """Download and verify updated community rules."""
    ri = RuleIntegrity()
    result = ri.update(force=args.force)
    print(json.dumps(result, indent=2))
    if result.get("status") == "integrity_failed":
        raise SystemExit(1)


def command_verify(_: argparse.Namespace) -> None:
    """Verify integrity of local community rules."""
    ri = RuleIntegrity()
    status = ri.status()
    print(json.dumps(status, indent=2))
    if status["integrity"] != "ok":
        print("\n⚠  Integrity check FAILED — rules may have been tampered with.")
        raise SystemExit(1)
    print("\n✓  All rule files verified successfully.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ADR Monitoring Agent CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="Start monitoring agent")
    p_start.add_argument("--daemon", action="store_true", help="Run in background daemon mode")
    p_start.add_argument("--no-stream", action="store_true", help="Disable real-time event feed")
    p_start.set_defaults(func=command_start)

    p_run = sub.add_parser("run", help="Internal run command used by daemon mode")
    p_run.add_argument("--no-stream", action="store_true", help="Disable real-time event feed")
    p_run.set_defaults(func=command_run)

    p_stop = sub.add_parser("stop", help="Stop daemonized monitoring agent")
    p_stop.set_defaults(func=command_stop)

    p_status = sub.add_parser("status", help="Show monitoring agent status")
    p_status.set_defaults(func=command_status)

    p_stats = sub.add_parser("stats", help="Show event statistics")
    p_stats.set_defaults(func=command_stats)

    p_update = sub.add_parser("update", help="Download and verify updated community rules")
    p_update.add_argument("--force", action="store_true", help="Force re-download even if up to date")
    p_update.set_defaults(func=command_update)

    p_verify = sub.add_parser("verify", help="Verify integrity of local community rules")
    p_verify.set_defaults(func=command_verify)

    p_config = sub.add_parser("config", help="Configure watched directories and settings")
    config_sub = p_config.add_subparsers(dest="config_action", required=True)

    c_show = config_sub.add_parser("show", help="Show full config")
    c_show.set_defaults(func=command_config)

    c_add = config_sub.add_parser("add-watch", help="Add watched directory")
    c_add.add_argument("path", help="Directory path")
    c_add.set_defaults(func=command_config)

    c_remove = config_sub.add_parser("remove-watch", help="Remove watched directory")
    c_remove.add_argument("path", help="Directory path")
    c_remove.set_defaults(func=command_config)

    c_set = config_sub.add_parser("set", help="Set config key with dot notation")
    c_set.add_argument("key", help="Config key like detection.unusual_api_call_volume.threshold_count")
    c_set.add_argument("value", help="JSON value or raw string")
    c_set.set_defaults(func=command_config)

    return parser


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
