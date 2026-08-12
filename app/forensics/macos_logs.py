from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineEvent, TimelineStore


class MacOSLogAdapter:
    """Read-only adapter for macOS Unified Logging via /usr/bin/log."""

    LOG_BINARY = "/usr/bin/log"

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.timeline = TimelineStore(self.case_dir)

    def collect(
        self,
        *,
        last: str = "5m",
        predicate: str | None = None,
        include_info: bool = True,
        max_events: int = 1000,
    ) -> dict[str, Any]:
        if max_events < 1 or max_events > 10000:
            raise ValueError("max_events must be between 1 and 10000")
        if not self._valid_last(last):
            raise ValueError("last must look like 30s, 5m, 2h, 1d, or boot")

        args = [
            self.LOG_BINARY,
            "show",
            "--style",
            "ndjson",
            "--no-pager",
            "--last",
            last,
        ]
        if include_info:
            args.append("--info")
        if predicate:
            args.extend(["--predicate", predicate])

        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "macOS log command failed")

        events: list[TimelineEvent] = []
        skipped = 0
        for line in completed.stdout.splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if row.get("finished"):
                continue
            event = self._normalize(row)
            if event is None:
                skipped += 1
                continue
            events.append(event)
            if len(events) >= max_events:
                break

        ingested = self.timeline.extend(events)
        return {
            "source": "macos_unified_log",
            "last": last,
            "predicate": predicate,
            "events_ingested": ingested,
            "skipped": skipped,
            "timeline_path": str(self.timeline.path.resolve()),
        }

    @staticmethod
    def _valid_last(value: str) -> bool:
        if value == "boot":
            return True
        if len(value) < 2:
            return False
        return value[:-1].isdigit() and value[-1] in {"s", "m", "h", "d"}

    @staticmethod
    def _normalize(row: dict[str, Any]) -> TimelineEvent | None:
        timestamp = row.get("timestamp")
        if not timestamp:
            return None

        message = str(row.get("eventMessage") or row.get("message") or "").strip()
        process = str(row.get("process") or row.get("processImagePath") or "").strip()
        subsystem = str(row.get("subsystem") or "").strip()
        category = str(row.get("category") or "").strip()
        message_type = str(row.get("messageType") or row.get("eventType") or "log").lower()

        summary_parts = [part for part in [process, message] if part]
        summary = ": ".join(summary_parts) if summary_parts else "macOS log event"

        return TimelineEvent(
            timestamp=TimelineStore.normalize_timestamp(str(timestamp)),
            source="macos_unified_log",
            event_type=message_type or "log",
            summary=summary[:1000],
            details={
                "process": process,
                "process_id": row.get("processID"),
                "subsystem": subsystem,
                "category": category,
                "message": message,
                "sender_image_path": row.get("senderImagePath"),
                "thread_id": row.get("threadID"),
            },
        )
