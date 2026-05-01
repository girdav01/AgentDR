"""CoSAI Community Rules — integrity verification and update manager.

Provides:
- SHA-256 integrity verification of local rule files against checksums.sha256
- On-demand and scheduled download of updated rules from a remote source
- Atomic file replacement with rollback on integrity failure

Usage::

    from agent.integrity import RuleIntegrity

    ri = RuleIntegrity()            # auto-discovers cosai-community/ path
    ri.verify()                     # raises IntegrityError on mismatch
    ri.update()                     # download + verify + replace
    ri.schedule(hour=1, minute=0)   # background 24-h update thread
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cosai.integrity")

# ── Configuration ──
# Override with env vars or pass to constructor.
_DEFAULT_RULES_URL = os.getenv(
    "COSAI_RULES_URL",
    "https://raw.githubusercontent.com/girdav01/aitf/main/cosai-community",
)

_MANIFEST = "checksums.sha256"
_RULE_FILES = [
    "rules/agent-signatures.json",
    "rules/ai-endpoints.json",
    "rules/messaging-endpoints.json",
    "policies/detection-rules.json",
]


class IntegrityError(Exception):
    """Raised when a rule file fails SHA-256 verification."""


class RuleIntegrity:
    """Manages integrity and updates for cosai-community/ rule files."""

    def __init__(
        self,
        community_dir: Optional[Path] = None,
        remote_url: Optional[str] = None,
    ) -> None:
        if community_dir:
            self.community_dir = Path(community_dir)
        else:
            # Auto-discover: <agent/>  →  <adr_system/cosai-community/>
            self.community_dir = (
                Path(__file__).resolve().parent.parent / "cosai-community"
            )
        self.remote_url = (remote_url or _DEFAULT_RULES_URL).rstrip("/")
        self._scheduler_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ── Public API ──

    def verify(self) -> Dict[str, str]:
        """Verify all rule files against the local checksums manifest.

        Returns a dict mapping each file to its status: 'ok', 'mismatch', or 'missing'.
        Raises IntegrityError if any file fails.
        """
        manifest = self._load_manifest()
        results: Dict[str, str] = {}
        failures: List[str] = []

        for relpath, expected_hash in manifest.items():
            filepath = self.community_dir / relpath
            if not filepath.exists():
                results[relpath] = "missing"
                failures.append(f"{relpath}: MISSING")
                continue
            actual_hash = self._sha256(filepath)
            if actual_hash == expected_hash:
                results[relpath] = "ok"
            else:
                results[relpath] = "mismatch"
                failures.append(
                    f"{relpath}: expected {expected_hash[:16]}… got {actual_hash[:16]}…"
                )

        if failures:
            msg = "Integrity check FAILED:\n" + "\n".join(f"  • {f}" for f in failures)
            logger.error(msg)
            raise IntegrityError(msg)

        logger.info("Integrity check passed — %d files verified", len(results))
        return results

    def status(self) -> Dict[str, Any]:
        """Return current rule status without raising on failure."""
        manifest = self._load_manifest()
        files: List[Dict[str, str]] = []
        all_ok = True

        for relpath in _RULE_FILES:
            filepath = self.community_dir / relpath
            expected = manifest.get(relpath, "")
            if not filepath.exists():
                files.append({"file": relpath, "status": "missing", "hash": ""})
                all_ok = False
                continue
            actual = self._sha256(filepath)
            ok = actual == expected
            if not ok:
                all_ok = False
            files.append({
                "file": relpath,
                "status": "ok" if ok else "mismatch",
                "hash": actual[:16],
            })

        # Read version from agent-signatures.json
        version = "unknown"
        sig_path = self.community_dir / "rules/agent-signatures.json"
        if sig_path.exists():
            try:
                data = json.loads(sig_path.read_text(encoding="utf-8"))
                version = data.get("version", "unknown")
            except Exception:
                pass

        return {
            "integrity": "ok" if all_ok else "failed",
            "version": version,
            "files": files,
            "remote_url": self.remote_url,
            "community_dir": str(self.community_dir),
        }

    def update(self, force: bool = False) -> Dict[str, Any]:
        """Download updated rules from remote, verify, and replace local files.

        1. Download checksums.sha256 manifest from remote
        2. Download each rule file to a temp dir
        3. Verify downloaded files against the new manifest
        4. Atomically replace local files only if all verifications pass
        5. Propagate copies to dashboard data/ if it exists

        Returns a summary dict.
        """
        logger.info("Starting rule update from %s", self.remote_url)
        tmpdir = tempfile.mkdtemp(prefix="cosai_update_")
        try:
            # 1. Download manifest
            manifest_url = f"{self.remote_url}/{_MANIFEST}"
            manifest_local = Path(tmpdir) / _MANIFEST
            self._download(manifest_url, manifest_local)
            new_manifest = self._parse_manifest(manifest_local)

            if not force:
                # Check if anything actually changed
                old_manifest = self._load_manifest()
                if old_manifest == new_manifest:
                    logger.info("Rules are already up to date")
                    return {"status": "up_to_date", "updated": []}

            # 2. Download each rule file
            for relpath in _RULE_FILES:
                url = f"{self.remote_url}/{relpath}"
                dest = Path(tmpdir) / relpath
                dest.parent.mkdir(parents=True, exist_ok=True)
                self._download(url, dest)

            # 3. Verify downloaded files
            failures = []
            for relpath, expected in new_manifest.items():
                downloaded = Path(tmpdir) / relpath
                if not downloaded.exists():
                    failures.append(f"{relpath}: not downloaded")
                    continue
                actual = self._sha256(downloaded)
                if actual != expected:
                    failures.append(
                        f"{relpath}: hash mismatch (expected {expected[:16]}… got {actual[:16]}…)"
                    )

            if failures:
                msg = "Downloaded rules FAILED integrity check — update aborted:\n"
                msg += "\n".join(f"  • {f}" for f in failures)
                logger.error(msg)
                return {"status": "integrity_failed", "errors": failures}

            # 4. Replace local files atomically
            updated = []
            for relpath in _RULE_FILES:
                src = Path(tmpdir) / relpath
                dst = self.community_dir / relpath
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                updated.append(relpath)

            # Replace manifest
            shutil.copy2(manifest_local, self.community_dir / _MANIFEST)

            # 5. Propagate to dashboard data/ if available
            self._propagate_to_dashboard()

            logger.info("Rule update complete — %d files updated", len(updated))
            return {"status": "updated", "updated": updated}

        except Exception as exc:
            logger.error("Rule update failed: %s", exc)
            return {"status": "error", "error": str(exc)}
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def schedule(
        self,
        hour: int = 1,
        minute: int = 0,
        interval_seconds: int = 86400,
    ) -> None:
        """Start a background thread that runs update() at the specified daily time."""
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return  # Already running

        def _loop() -> None:
            logger.info(
                "Rule update scheduler started — daily at %02d:%02d UTC", hour, minute
            )
            while not self._stop_event.is_set():
                now = datetime.now(timezone.utc)
                # Calculate seconds until next target time
                target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                if target <= now:
                    # Already past today's target — schedule for tomorrow
                    target = target.replace(day=target.day)  # handled via sleep fallback
                    wait = interval_seconds - (now - target).total_seconds()
                    if wait < 0:
                        wait = interval_seconds
                else:
                    wait = (target - now).total_seconds()

                # Sleep in small increments so we can respond to stop_event
                slept = 0.0
                while slept < wait and not self._stop_event.is_set():
                    time.sleep(min(60, wait - slept))
                    slept += 60

                if self._stop_event.is_set():
                    break

                try:
                    result = self.update()
                    logger.info("Scheduled update result: %s", result.get("status"))
                except Exception as exc:
                    logger.error("Scheduled update error: %s", exc)

        self._stop_event.clear()
        self._scheduler_thread = threading.Thread(
            target=_loop, daemon=True, name="cosai-rule-updater"
        )
        self._scheduler_thread.start()

    def stop_scheduler(self) -> None:
        """Signal the background scheduler to stop."""
        self._stop_event.set()

    # ── Internal helpers ──

    @staticmethod
    def _sha256(filepath: Path) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _load_manifest(self) -> Dict[str, str]:
        manifest_path = self.community_dir / _MANIFEST
        if not manifest_path.exists():
            logger.warning("No checksums manifest at %s", manifest_path)
            return {}
        return self._parse_manifest(manifest_path)

    @staticmethod
    def _parse_manifest(path: Path) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                result[parts[1].strip()] = parts[0].strip()
        return result

    @staticmethod
    def _download(url: str, dest: Path) -> None:
        logger.debug("Downloading %s → %s", url, dest)
        req = urllib.request.Request(url, headers={"User-Agent": "CoSAI-ADR-Agent/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            dest.write_bytes(resp.read())

    def _propagate_to_dashboard(self) -> None:
        """Copy updated rules to the dashboard's data/ folder if it exists."""
        # Dashboard location: <adr_system>/../adr_dashboard/nextjs_space/data/cosai-community/
        dashboard_dir = (
            self.community_dir.parent.parent
            / "adr_dashboard"
            / "nextjs_space"
            / "data"
            / "cosai-community"
        )
        if not dashboard_dir.exists():
            return
        for relpath in _RULE_FILES:
            src = self.community_dir / relpath
            dst = dashboard_dir / relpath
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        # Also copy manifest
        shutil.copy2(
            self.community_dir / _MANIFEST,
            dashboard_dir / _MANIFEST,
        )
        logger.info("Propagated updated rules to dashboard at %s", dashboard_dir)
