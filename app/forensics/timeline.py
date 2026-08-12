from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class TimelineEvent:
    timestamp: str
    source: str
    event_type: str
    summary: str
    details: dict[str, Any]
    evidence_id: str | None = None


class TimelineStore:
    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.path = self.case_dir / "timeline.jsonl"
        self.case_dir.mkdir(parents=True, exist_ok=True)

    def append(self, event: TimelineEvent) -> dict[str, Any]:
        payload = asdict(event)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
        return payload

    def extend(self, events: Iterable[TimelineEvent]) -> int:
        count = 0
        for event in events:
            self.append(event)
            count += 1
        return count

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return sorted(rows, key=lambda item: item.get("timestamp") or "")

    @staticmethod
    def normalize_timestamp(value: str | None) -> str:
        if not value:
            return datetime.now(timezone.utc).isoformat()
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
