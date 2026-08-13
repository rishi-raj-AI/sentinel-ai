from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(slots=True)
class FusionSignal:
    source: str
    category: str
    summary: str
    confidence: float
    severity: float
    evidence: list[str]
    entities: list[str]
    contradicting: list[str]
    gaps: list[str]


class SecurityFusionEngine:
    """Cross-domain SOC fusion for defensive triage and escalation decisions."""

    VERSION = "X9.0"
    SOURCE_WEIGHTS = {
        "dfir": 1.0,
        "soc": 0.95,
        "appsec": 0.85,
        "artifact": 0.85,
        "identity": 0.9,
        "cloud": 0.9,
        "knowledge": 0.8,
        "digital-twin": 0.8,
    }

    @staticmethod
    def _clamp(v: float) -> float:
        return max(0.0, min(1.0, float(v)))

    def fuse(self, signals: list[FusionSignal], *, objective: str = "Assess security posture") -> dict[str, Any]:
        if not signals:
            return {"version": self.VERSION, "objective": objective, "score": 0.0, "decision": "insufficient-data", "signals": []}
        weighted = []
        evidence: list[str] = []
        contradictions: list[str] = []
        gaps: list[str] = []
        entities: set[str] = set()
        categories: dict[str, int] = {}
        for s in signals:
            source_weight = self.SOURCE_WEIGHTS.get(s.source.casefold(), 0.7)
            conf = self._clamp(s.confidence)
            sev = self._clamp(s.severity)
            value = conf * sev * source_weight
            weighted.append(value)
            evidence.extend(s.evidence)
            contradictions.extend(s.contradicting)
            gaps.extend(s.gaps)
            entities.update(s.entities)
            categories[s.category] = categories.get(s.category, 0) + 1
        base = sum(weighted) / len(weighted)
        diversity_bonus = min(0.18, max(0, len(categories)-1) * 0.04)
        evidence_bonus = min(0.15, len(set(evidence)) * 0.015)
        contradiction_penalty = min(0.35, len(set(contradictions)) * 0.07)
        gap_penalty = min(0.25, len(set(gaps)) * 0.05)
        score = self._clamp(base + diversity_bonus + evidence_bonus - contradiction_penalty - gap_penalty)
        if score >= 0.75:
            decision = "high-priority-review"
        elif score >= 0.5:
            decision = "investigate"
        elif score >= 0.25:
            decision = "monitor-and-enrich"
        else:
            decision = "low-confidence"
        return {
            "version": self.VERSION,
            "objective": objective,
            "score": round(score,3),
            "decision": decision,
            "signals": [asdict(s) for s in signals],
            "evidence": list(dict.fromkeys(evidence)),
            "contradictions": list(dict.fromkeys(contradictions)),
            "gaps": list(dict.fromkeys(gaps)),
            "entities": sorted(entities),
            "categories": categories,
            "components": {
                "mean_weighted_signal": round(base,3),
                "diversity_bonus": round(diversity_bonus,3),
                "evidence_bonus": round(evidence_bonus,3),
                "contradiction_penalty": round(contradiction_penalty,3),
                "gap_penalty": round(gap_penalty,3),
            },
            "policy": {
                "decision_support_only": True,
                "automatic_remediation": False,
                "evidence_and_counter_evidence_preserved": True,
            },
        }
