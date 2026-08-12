from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineEvent, TimelineStore


def import_jsonl_events(
    case_dir: str | Path,
    source_path: str,
    *,
    source_name: str = "jsonl",
    evidence_id: str | None = None,
) -> dict[str, Any]:
    target = Path(source_path).expanduser().resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Event file not found: {target}")

    store = TimelineStore(case_dir)
    events: list[TimelineEvent] = []

    for index, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        timestamp = TimelineStore.normalize_timestamp(payload.get("timestamp"))
        event_type = str(payload.get("event_type") or payload.get("type") or "event")
        summary = str(payload.get("summary") or payload.get("message") or f"event {index}")
        events.append(
            TimelineEvent(
                timestamp=timestamp,
                source=source_name,
                event_type=event_type,
                summary=summary,
                details=payload,
                evidence_id=evidence_id,
            )
        )

    count = store.extend(events)
    return {
        "source": source_name,
        "path": str(target),
        "events_ingested": count,
        "timeline_path": str(store.path.resolve()),
    }


def timeline_summary(case_dir: str | Path) -> dict[str, Any]:
    events = TimelineStore(case_dir).read()
    by_source: dict[str, int] = {}
    by_type: dict[str, int] = {}

    for event in events:
        by_source[event["source"]] = by_source.get(event["source"], 0) + 1
        by_type[event["event_type"]] = by_type.get(event["event_type"], 0) + 1

    return {
        "event_count": len(events),
        "first_event": events[0]["timestamp"] if events else None,
        "last_event": events[-1]["timestamp"] if events else None,
        "by_source": by_source,
        "by_type": by_type,
        "events": events,
    }
