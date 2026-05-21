from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import psutil


def read_pid(pid_file: Path) -> Optional[int]:
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def write_pid(pid_file: Path, pid: int) -> None:
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(pid), encoding="utf-8")


def remove_pid(pid_file: Path) -> None:
    if pid_file.exists():
        pid_file.unlink(missing_ok=True)


def is_process_running(pid: int) -> bool:
    try:
        return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
    except Exception:
        return False


def start_daemon(project_root: Path, pid_file: Path, runtime_log: Path) -> Dict[str, Any]:
    existing_pid = read_pid(pid_file)
    if existing_pid and is_process_running(existing_pid):
        return {"ok": False, "message": f"Agent already running with PID {existing_pid}"}

    runtime_log.parent.mkdir(parents=True, exist_ok=True)
    with runtime_log.open("a", encoding="utf-8") as out:
        proc = subprocess.Popen(
            [sys.executable, "-m", "agent.main", "run", "--no-stream"],
            cwd=str(project_root),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=out,
            start_new_session=True,
            env=os.environ.copy(),
            text=True,
        )

    time.sleep(1.2)
    if proc.poll() is not None:
        return {"ok": False, "message": "Agent failed to start. Check runtime log."}

    write_pid(pid_file, proc.pid)
    return {"ok": True, "message": f"Agent started in daemon mode with PID {proc.pid}", "pid": proc.pid}


def stop_daemon(pid_file: Path, timeout_seconds: int = 8) -> Dict[str, Any]:
    pid = read_pid(pid_file)
    if not pid:
        return {"ok": False, "message": "No PID file found. Agent may not be running."}

    if not is_process_running(pid):
        remove_pid(pid_file)
        return {"ok": False, "message": f"Stale PID file removed (PID {pid} not running)."}

    try:
        proc = psutil.Process(pid)
        children = proc.children(recursive=True)
        proc.terminate()
        for child in children:
            child.terminate()

        gone, alive = psutil.wait_procs([proc, *children], timeout=timeout_seconds)
        for p in alive:
            p.kill()
        remove_pid(pid_file)
        return {"ok": True, "message": f"Stopped agent PID {pid}"}
    except Exception as exc:
        return {"ok": False, "message": f"Failed to stop PID {pid}: {exc}"}


def daemon_status(pid_file: Path) -> Dict[str, Any]:
    pid = read_pid(pid_file)
    if not pid:
        return {"running": False, "message": "Agent is not running (no PID file)."}
    if not is_process_running(pid):
        remove_pid(pid_file)
        return {"running": False, "message": "Agent is not running (stale PID cleaned)."}
    try:
        proc = psutil.Process(pid)
        return {
            "running": True,
            "pid": pid,
            "started_at": proc.create_time(),
            "cmdline": proc.cmdline(),
        }
    except Exception:
        return {"running": True, "pid": pid}
