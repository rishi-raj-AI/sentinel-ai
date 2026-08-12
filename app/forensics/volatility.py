from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineEvent, TimelineStore


class VolatilityAdapter:
    """Controlled Volatility 3 adapter for authorized memory-image analysis.

    Only a small allowlist of read-only discovery plugins is exposed. Plugin output
    is requested as JSON and normalized into the case timeline.
    """

    ALLOWED_PLUGINS = {
        "windows.info": "system",
        "windows.pslist": "process",
        "windows.pstree": "process",
        "windows.cmdline": "process",
        "windows.netscan": "network",
        "windows.dlllist": "module",
    }

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.store = TimelineStore(case_dir)

    @staticmethod
    def executable() -> str | None:
        return shutil.which("vol") or shutil.which("vol.py")

    @classmethod
    def status(cls) -> dict[str, Any]:
        executable = cls.executable()
        if not executable:
            return {
                "available": False,
                "executable": None,
                "message": "Volatility 3 CLI not found on PATH",
            }
        completed = subprocess.run(
            [executable, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "available": completed.returncode == 0,
            "executable": executable,
            "return_code": completed.returncode,
        }

    @staticmethod
    def _summary(plugin: str, row: dict[str, Any]) -> str:
        preferred = (
            "ImageFileName",
            "Name",
            "ImageFileName",
            "Process",
            "CommandLine",
            "LocalAddr",
            "ForeignAddr",
            "Path",
        )
        parts: list[str] = []
        for key in preferred:
            value = row.get(key)
            if value not in (None, "", "N/A"):
                parts.append(f"{key}={value}")
            if len(parts) >= 3:
                break
        return f"{plugin}: " + (", ".join(parts) if parts else "artifact")

    def run(
        self,
        image_path: str,
        plugin: str,
        *,
        evidence_id: str | None = None,
        timeout_seconds: int = 600,
        max_rows: int = 5000,
    ) -> dict[str, Any]:
        executable = self.executable()
        if not executable:
            raise RuntimeError("Volatility 3 is not installed or 'vol' is not on PATH")
        if plugin not in self.ALLOWED_PLUGINS:
            raise ValueError(f"Plugin not allowed: {plugin}")

        image = Path(image_path).expanduser().resolve()
        if not image.is_file():
            raise FileNotFoundError(f"Memory image not found: {image}")

        command = [
            executable,
            "-q",
            "-r",
            "json",
            "-f",
            str(image),
            plugin,
        ]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"Volatility exited {completed.returncode}")

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Volatility did not return valid JSON") from exc

        rows = payload if isinstance(payload, list) else [payload]
        rows = rows[:max_rows]
        event_type = self.ALLOWED_PLUGINS[plugin]
        events: list[TimelineEvent] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            timestamp = row.get("CreateTime") or row.get("Created") or row.get("Time")
            events.append(
                TimelineEvent(
                    timestamp=TimelineStore.normalize_timestamp(str(timestamp) if timestamp else None),
                    source=f"volatility:{plugin}",
                    event_type=event_type,
                    summary=self._summary(plugin, row),
                    details=row,
                    evidence_id=evidence_id,
                )
            )

        ingested = self.store.extend(events)
        return {
            "plugin": plugin,
            "image_path": str(image),
            "rows_returned": len(rows),
            "events_ingested": ingested,
            "rows_truncated": len(payload) > max_rows if isinstance(payload, list) else False,
        }
