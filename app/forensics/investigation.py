from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.forensics.correlation import CorrelationEngine
from app.forensics.timeline import TimelineStore


@dataclass(slots=True)
class Finding:
    title: str
    severity: str
    confidence: str
    reason: str
    events: list[dict[str, Any]]
    score: int


class InvestigationEngine:
    """Convert normalized forensic events into compact investigator findings.

    This layer is deterministic and deliberately conservative: routine operating-
    system errors should not become high-severity security findings without
    corroborating behavior.
    """

    PRIORITY_BY_TYPE: dict[str, int] = {
        "login": 7,
        "authentication": 8,
        "process": 7,
        "network": 8,
        "file": 6,
        "persistence": 10,
        "error": 3,
        "fault": 4,
        "default": 1,
        "info": 1,
        "activitycreateevent": 1,
        "stateevent": 1,
    }

    HIGH_VALUE_TERMS: dict[str, int] = {
        "failed login": 5,
        "authentication failure": 5,
        "denied login": 5,
        "outbound connection": 4,
        "external connection": 4,
        "remote connection": 3,
        "powershell": 5,
        "osascript": 4,
        "curl ": 3,
        "wget ": 3,
        "launch agent": 5,
        "launchdaemon": 5,
        "unsigned executable": 5,
        "malware": 6,
    }

    BENIGN_TERMS: dict[str, int] = {
        "sandbox restriction": -4,
        "deny(1) mach-lookup": -4,
        "contactspersistence.framework": -4,
        "com.apple.contactsd.persistence": -4,
        "speechrecognitioncore": -2,
        "windowserver": -2,
    }

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.store = TimelineStore(case_dir)

    @classmethod
    def score_event(cls, event: dict[str, Any]) -> int:
        event_type = str(event.get("event_type", "unknown")).lower()
        text = f"{event.get('summary', '')} {event.get('details', {})}".lower()
        score = cls.PRIORITY_BY_TYPE.get(event_type, 2)
        for term, weight in cls.HIGH_VALUE_TERMS.items():
            if term in text:
                score += weight
        for term, weight in cls.BENIGN_TERMS.items():
            if term in text:
                score += weight
        return max(0, min(score, 20))

    @staticmethod
    def _confidence(score: int, event_count: int, distinct_types: int = 1) -> str:
        if score >= 16 and distinct_types >= 2:
            return "high"
        if score >= 9 or (event_count >= 2 and distinct_types >= 2):
            return "medium"
        return "low"

    def _single_event_findings(self, events: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for event in events:
            score = self.score_event(event)
            if score < 8:
                continue
            event_type = str(event.get("event_type", "unknown")).lower()
            summary = str(event.get("summary", ""))
            findings.append(
                Finding(
                    title=f"Priority {event_type} event",
                    severity="high" if score >= 14 else "medium",
                    confidence=self._confidence(score, 1),
                    reason=summary or f"High-priority {event_type} event observed",
                    events=[event],
                    score=score,
                )
            )
        return findings

    def _sequence_findings(self, events: list[dict[str, Any]], window_seconds: int) -> list[Finding]:
        findings: list[Finding] = []
        important = [event for event in events if self.score_event(event) >= 6]
        for idx, first in enumerate(important):
            first_time = CorrelationEngine._dt(first["timestamp"])
            chain = [first]
            seen_types = {str(first.get("event_type", "unknown"))}
            for candidate in important[idx + 1 :]:
                delta = (CorrelationEngine._dt(candidate["timestamp"]) - first_time).total_seconds()
                if delta < 0:
                    continue
                if delta > window_seconds:
                    break
                candidate_type = str(candidate.get("event_type", "unknown"))
                if candidate_type != str(chain[-1].get("event_type", "unknown")):
                    chain.append(candidate)
                    seen_types.add(candidate_type)
                if len(chain) >= 4:
                    break
            if len(chain) < 2 or len(seen_types) < 2:
                continue

            types = [str(item.get("event_type", "unknown")) for item in chain]
            total_score = sum(self.score_event(item) for item in chain)
            distinct_types = len(set(types))
            high_confidence = total_score >= 26 and distinct_types >= 3
            findings.append(
                Finding(
                    title=" → ".join(types),
                    severity="high" if high_confidence else "medium",
                    confidence=self._confidence(total_score, len(chain), distinct_types),
                    reason=(
                        f"{len(chain)} relevant events across {distinct_types} event types "
                        f"occurred within {window_seconds} seconds"
                    ),
                    events=chain,
                    score=min(total_score, 40),
                )
            )
        return findings

    @staticmethod
    def _deduplicate_findings(findings: list[Finding], limit: int) -> list[Finding]:
        seen: set[tuple[str, str]] = set()
        kept: list[Finding] = []
        for finding in sorted(findings, key=lambda item: item.score, reverse=True):
            first_ts = finding.events[0].get("timestamp", "") if finding.events else ""
            key = (finding.title, str(first_ts))
            if key in seen:
                continue
            seen.add(key)
            kept.append(finding)
            if len(kept) >= limit:
                break
        return kept

    def analyze(
        self,
        *,
        window_seconds: int = 120,
        max_findings: int = 25,
        minimum_priority: int = 4,
    ) -> dict[str, Any]:
        events = self.store.read()
        scored = [(self.score_event(event), event) for event in events]
        relevant = [event for score, event in scored if score >= minimum_priority]
        noise_removed = len(events) - len(relevant)

        findings = self._single_event_findings(relevant)
        findings.extend(self._sequence_findings(relevant, window_seconds))
        findings = self._deduplicate_findings(findings, max_findings)

        severity_counts = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        top_scores = sorted((score for score, _ in scored), reverse=True)[:10]
        overall = "no high-priority findings"
        if severity_counts.get("high", 0):
            overall = "high-priority activity requires review"
        elif severity_counts.get("medium", 0):
            overall = "some activity warrants investigator review"

        return {
            "raw_event_count": len(events),
            "relevant_event_count": len(relevant),
            "noise_removed": noise_removed,
            "findings": [asdict(finding) for finding in findings],
            "summary": {
                "finding_count": len(findings),
                "severity_counts": severity_counts,
                "top_event_scores": top_scores,
                "window_seconds": window_seconds,
                "minimum_priority": minimum_priority,
                "overall_assessment": overall,
            },
        }
