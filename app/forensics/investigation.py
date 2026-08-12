from __future__ import annotations

from dataclasses import dataclass, asdict
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

    This layer is intentionally deterministic. It prioritizes events and creates
    human-review findings without using an LLM, so later AI summaries can be
    grounded in reproducible evidence.
    """

    PRIORITY_BY_TYPE: dict[str, int] = {
        "login": 7,
        "authentication": 8,
        "process": 7,
        "network": 8,
        "file": 6,
        "persistence": 10,
        "error": 4,
        "fault": 5,
        "default": 1,
        "info": 1,
        "activitycreateevent": 1,
        "stateevent": 1,
    }

    HIGH_VALUE_TERMS: dict[str, int] = {
        "failed login": 5,
        "authentication failure": 5,
        "denied login": 5,
        "outbound": 3,
        "external": 3,
        "remote": 2,
        "powershell": 5,
        "osascript": 4,
        "curl ": 3,
        "wget ": 3,
        "launch agent": 5,
        "launchdaemon": 5,
        "persistence": 5,
        "unsigned": 4,
        "malware": 6,
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
        return min(score, 20)

    @staticmethod
    def _confidence(score: int, event_count: int) -> str:
        if score >= 14 or event_count >= 3:
            return "high"
        if score >= 8 or event_count >= 2:
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
            for candidate in important[idx + 1 :]:
                delta = (CorrelationEngine._dt(candidate["timestamp"]) - first_time).total_seconds()
                if delta < 0:
                    continue
                if delta > window_seconds:
                    break
                if candidate.get("event_type") != chain[-1].get("event_type"):
                    chain.append(candidate)
                if len(chain) >= 4:
                    break
            if len(chain) < 2:
                continue
            types = [str(item.get("event_type", "unknown")) for item in chain]
            total_score = sum(self.score_event(item) for item in chain)
            findings.append(
                Finding(
                    title=" → ".join(types),
                    severity="high" if total_score >= 24 else "medium",
                    confidence=self._confidence(total_score, len(chain)),
                    reason=f"{len(chain)} higher-priority events occurred within {window_seconds} seconds",
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
