from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineStore


class CorrelationEngine:
    def __init__(self, case_dir: str | Path) -> None:
        self.store = TimelineStore(case_dir)

    @staticmethod
    def _dt(value: str) -> datetime:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))

    def analyze(self, window_seconds: int = 300) -> dict[str, Any]:
        events = self.store.read()
        if not events:
            return {
                "event_count": 0,
                "sequence": [],
                "relationships": [],
                "anomalies": [],
                "summary": {"by_type": {}, "by_source": {}},
            }

        by_type = Counter(event.get("event_type", "unknown") for event in events)
        by_source = Counter(event.get("source", "unknown") for event in events)

        sequence = [
            {
                "index": index,
                "timestamp": event["timestamp"],
                "event_type": event.get("event_type"),
                "source": event.get("source"),
                "summary": event.get("summary"),
            }
            for index, event in enumerate(events, start=1)
        ]

        relationships: list[dict[str, Any]] = []
        for left_index, left in enumerate(events):
            left_time = self._dt(left["timestamp"])
            for right in events[left_index + 1 :]:
                delta = (self._dt(right["timestamp"]) - left_time).total_seconds()
                if delta < 0:
                    continue
                if delta > window_seconds:
                    break
                if left.get("event_type") != right.get("event_type"):
                    relationships.append(
                        {
                            "from_type": left.get("event_type"),
                            "from_summary": left.get("summary"),
                            "to_type": right.get("event_type"),
                            "to_summary": right.get("summary"),
                            "delta_seconds": delta,
                        }
                    )

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
            "first_event": events[0]["timestamp"],
            "last_event": events[-1]["timestamp"],
            "sequence": sequence,
            "relationships": relationships,
            "anomalies": anomalies,
            "summary": {
                "by_type": dict(by_type),
                "by_source": dict(by_source),
                "relationship_count": len(relationships),
                "anomaly_count": len(anomalies),
                "window_seconds": window_seconds,
            },
        }
