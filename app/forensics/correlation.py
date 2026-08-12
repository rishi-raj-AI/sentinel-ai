from __future__ import annotations

from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineStore


class CorrelationEngine:
    DEFAULT_MAX_EVENTS = 5_000
    DEFAULT_MAX_RELATIONSHIPS = 2_000
    DEFAULT_SEQUENCE_LIMIT = 500
    DEFAULT_DEDUP_SECONDS = 1.0

    def __init__(self, case_dir: str | Path) -> None:
        self.store = TimelineStore(case_dir)

    @staticmethod
    def _dt(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    @staticmethod
    def _fingerprint(event: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(event.get("source", "")),
            str(event.get("event_type", "")),
            str(event.get("summary", "")),
        )

    def _deduplicate(
        self, events: list[dict[str, Any]], dedup_seconds: float
    ) -> tuple[list[dict[str, Any]], int]:
        if dedup_seconds <= 0:
            return events, 0

        kept: list[dict[str, Any]] = []
        last_seen: dict[tuple[str, str, str], datetime] = {}
        removed = 0

        for event in events:
            fingerprint = self._fingerprint(event)
            current_time = self._dt(event["timestamp"])
            previous_time = last_seen.get(fingerprint)
            if previous_time is not None:
                delta = (current_time - previous_time).total_seconds()
                if 0 <= delta <= dedup_seconds:
                    removed += 1
                    last_seen[fingerprint] = current_time
                    continue
            kept.append(event)
            last_seen[fingerprint] = current_time

        return kept, removed

    def analyze(
        self,
        window_seconds: int = 300,
        *,
        max_events: int = DEFAULT_MAX_EVENTS,
        max_relationships: int = DEFAULT_MAX_RELATIONSHIPS,
        sequence_limit: int = DEFAULT_SEQUENCE_LIMIT,
        dedup_seconds: float = DEFAULT_DEDUP_SECONDS,
    ) -> dict[str, Any]:
        raw_events = self.store.read()
        if not raw_events:
            return {
                "event_count": 0,
                "raw_event_count": 0,
                "sequence": [],
                "relationships": [],
                "anomalies": [],
                "summary": {"by_type": {}, "by_source": {}},
            }

        events, duplicates_removed = self._deduplicate(raw_events, dedup_seconds)
        truncated = len(events) > max_events
        if truncated:
            # Analyze the most recent bounded slice. This keeps the command responsive
            # on high-volume sources such as macOS Unified Logs.
            events = events[-max_events:]

        by_type = Counter(event.get("event_type", "unknown") for event in events)
        by_source = Counter(event.get("source", "unknown") for event in events)

        sequence_events = events[:sequence_limit]
        sequence = [
            {
                "index": index,
                "timestamp": event["timestamp"],
                "event_type": event.get("event_type"),
                "source": event.get("source"),
                "summary": event.get("summary"),
            }
            for index, event in enumerate(sequence_events, start=1)
        ]

        relationships: list[dict[str, Any]] = []
        active: deque[tuple[datetime, dict[str, Any]]] = deque()

        for right in events:
            right_time = self._dt(right["timestamp"])
            cutoff_seconds = float(window_seconds)

            while active and (right_time - active[0][0]).total_seconds() > cutoff_seconds:
                active.popleft()

            for left_time, left in active:
                if len(relationships) >= max_relationships:
                    break
                if left.get("event_type") == right.get("event_type"):
                    continue
                delta = (right_time - left_time).total_seconds()
                if delta < 0:
                    continue
                relationships.append(
                    {
                        "from_type": left.get("event_type"),
                        "from_summary": left.get("summary"),
                        "to_type": right.get("event_type"),
                        "to_summary": right.get("summary"),
                        "delta_seconds": delta,
                    }
                )

            active.append((right_time, right))

        anomalies: list[dict[str, Any]] = []
        for event in events:
            event_type = str(event.get("event_type", "")).lower()
            text = f"{event.get('summary', '')} {event.get('details', {})}".lower()

            if event_type == "network" and any(term in text for term in ("outbound", "external", "remote")):
                anomalies.append(
                    {
                        "severity": "medium",
                        "reason": "Outbound or remote network activity",
                        "event": event,
                    }
                )
            if any(term in text for term in ("failed login", "authentication failure", "denied login")):
                anomalies.append(
                    {
                        "severity": "medium",
                        "reason": "Authentication failure observed",
                        "event": event,
                    }
                )
            if event_type == "process" and any(term in text for term in ("powershell", "osascript", "curl ", "wget ")):
                anomalies.append(
                    {
                        "severity": "medium",
                        "reason": "Process event contains a command/interpreter worth review",
                        "event": event,
                    }
                )

        return {
            "event_count": len(events),
            "raw_event_count": len(raw_events),
            "duplicates_removed": duplicates_removed,
            "analysis_truncated": truncated,
            "first_event": events[0]["timestamp"],
            "last_event": events[-1]["timestamp"],
            "sequence": sequence,
            "sequence_truncated": len(events) > sequence_limit,
            "relationships": relationships,
            "relationships_truncated": len(relationships) >= max_relationships,
            "anomalies": anomalies,
            "summary": {
                "by_type": dict(by_type),
                "by_source": dict(by_source),
                "relationship_count": len(relationships),
                "anomaly_count": len(anomalies),
                "window_seconds": window_seconds,
                "max_events": max_events,
                "max_relationships": max_relationships,
                "dedup_seconds": dedup_seconds,
            },
        }
