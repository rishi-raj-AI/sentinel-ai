from __future__ import annotations

from typing import Any, Iterable

from app.enterprise.core import InvestigationReasoningService as BaseReasoningService


class InvestigationReasoningService(BaseReasoningService):
    """Phase 5 precision layer for counter-evidence ranking and confidence.

    Generic timeline/event nodes are heavily penalized unless they match
    case-specific, non-generic terms. Confidence is derived from the weighted
    relevance of the top candidates rather than raw candidate count.
    """

    GENERIC_EVENT_PENALTY = 0.08
    CASE_SPECIFIC_TERMS = {"test", "validation", "false positive", "known", "update"}

    def counter_evidence(self, keywords: Iterable[str], *, limit: int = 50) -> list[dict[str, Any]]:
        rows = super().counter_evidence(keywords, limit=max(limit * 3, 50))
        rescored: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            node_type = str(item.get("type") or "").casefold()
            matched = [str(x).casefold() for x in item.get("matched_terms") or []]
            score = float(item.get("relevance_score") or 0.0)
            generic_only = bool(matched) and all(term in self.GENERIC_TERMS for term in matched)
            case_specific = any(term in self.CASE_SPECIFIC_TERMS for term in matched)

            if node_type == "event":
                if generic_only:
                    score *= self.GENERIC_EVENT_PENALTY
                elif not case_specific:
                    score *= 0.35
            elif node_type in {"yara_rule", "sigma_rule", "evidence"} and case_specific:
                score *= 1.35

            item["relevance_score"] = round(score, 3)
            components = dict(item.get("relevance_components") or {})
            components.update({
                "phase5_precision_rerank": True,
                "generic_event_penalty": self.GENERIC_EVENT_PENALTY if node_type == "event" and generic_only else 1.0,
                "case_specific_match": case_specific,
            })
            item["relevance_components"] = components
            rescored.append(item)

        rescored.sort(key=lambda row: (float(row.get("relevance_score") or 0.0), str(row.get("id") or "")), reverse=True)
        return rescored[:limit]

    @staticmethod
    def counter_evidence_confidence(rows: list[dict[str, Any]], *, top_k: int = 8) -> tuple[float, dict[str, Any]]:
        """Derive confidence from relevance quality, not candidate volume."""
        if not rows:
            return 0.0, {"top_k": top_k, "scores": [], "mean_top_score": 0.0, "high_quality_count": 0}
        scores = [max(0.0, float(row.get("relevance_score") or 0.0)) for row in rows[:top_k]]
        normalized = [min(1.0, score / 10.0) for score in scores]
        mean_top = sum(normalized) / len(normalized)
        high_quality = sum(score >= 0.6 for score in normalized)
        confidence = round(min(0.9, 0.15 + (0.65 * mean_top) + (0.02 * high_quality)), 3)
        return confidence, {
            "top_k": top_k,
            "scores": [round(score, 3) for score in scores],
            "normalized_scores": [round(score, 3) for score in normalized],
            "mean_top_score": round(mean_top, 3),
            "high_quality_count": high_quality,
            "candidate_count": len(rows),
            "method": "weighted_top_relevance",
        }


__all__ = ["InvestigationReasoningService"]
