from __future__ import annotations

from pathlib import Path
from typing import Any

from app.forensics.attack_mapping import AttackMappingEngine


class AttackChainEngine:
    """Build a conservative evidence-linked chain from ATT&CK candidates."""

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)

    @staticmethod
    def _timestamp(candidate: dict[str, Any]) -> str | None:
        for item in candidate.get("evidence", []):
            if isinstance(item, dict) and item.get("timestamp"):
                return str(item["timestamp"])
        return None

    @staticmethod
    def _evidence_ids(candidate: dict[str, Any]) -> list[str]:
        found: set[str] = set()
        for item in candidate.get("evidence", []):
            if not isinstance(item, dict):
                continue
            if item.get("evidence_id"):
                found.add(str(item["evidence_id"]))
            for value in item.get("evidence_ids", []) or []:
                found.add(str(value))
        return sorted(found)

    def build(self, *, max_candidates: int = 25) -> dict[str, Any]:
        mapping = AttackMappingEngine(self.case_dir).analyze(max_candidates=max_candidates)
        candidates = list(mapping.get("candidates", []))

        # Timestamped behavior is ordered chronologically. Untimestamped aggregate
        # candidates are appended as contextual stages, not presented as a proven
        # temporal sequence.
        timestamped = [c for c in candidates if self._timestamp(c)]
        contextual = [c for c in candidates if not self._timestamp(c)]
        timestamped.sort(key=lambda c: self._timestamp(c) or "")
        ordered = timestamped + contextual

        stages: list[dict[str, Any]] = []
        for index, candidate in enumerate(ordered, start=1):
            stages.append({
                "stage": index,
                "technique_id": candidate["technique_id"],
                "technique_name": candidate["technique_name"],
                "tactic": candidate["tactic"],
                "confidence": candidate["confidence"],
                "timestamp": self._timestamp(candidate),
                "evidence_ids": self._evidence_ids(candidate),
                "reason": candidate["reason"],
                "chronology_status": "observed_timestamp" if self._timestamp(candidate) else "context_only",
            })

        return {
            "stage_count": len(stages),
            "stages": stages,
            "summary": {
                "timestamped_stages": len(timestamped),
                "context_only_stages": len(contextual),
                "is_proven_attack_chain": False,
                "interpretation": (
                    "This is an evidence-linked behavior chain for investigator review; "
                    "it does not by itself prove compromise or adversary intent"
                ),
            },
        }
