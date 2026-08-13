from __future__ import annotations

from typing import Any

from app.forensics.case_copilot import CopilotSource
from app.forensics.case_copilot_v5 import (
    CaseCopilot as ProvenanceCaseCopilot,
    ModelProvider,
)
from app.forensics.claim_verifier import ClaimEvidenceVerifier


class CaseCopilot(ProvenanceCaseCopilot):
    """Claim-verified evidence-grounded copilot.

    v5 proves citations are valid and provenance-safe. v6 additionally verifies
    factual claims against the cited source content. Unsupported factual claims
    are removed from model output and preserved in an audit trail. If fewer than
    half of factual claims survive, Sentinel rejects the model synthesis and
    returns the deterministic grounded answer instead.
    """

    MIN_FACTUAL_SUPPORT_RATIO = 0.50

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        result = super().answer(question, max_sources=max_sources)
        result["claim_verification"] = None
        result["claim_verification_applied"] = False
        result["claim_verification_policy"] = {
            "enabled": True,
            "minimum_factual_support_ratio": self.MIN_FACTUAL_SUPPORT_RATIO,
            "unsupported_factual_claims_removed": True,
            "weak_model_synthesis_rejected": True,
        }

        if result.get("mode") != "model":
            return result

        sources = [
            CopilotSource(**row) if isinstance(row, dict) else row
            for row in result.get("sources", [])
        ]
        verifier = ClaimEvidenceVerifier(sources)
        verification = verifier.verify_answer(str(result.get("answer") or ""))
        result["claim_verification"] = verification
        result["claim_verification_applied"] = True

        ratio = float(verification.get("factual_claim_support_ratio", 0.0))
        sanitized = str(verification.get("answer") or "").strip()
        if ratio < self.MIN_FACTUAL_SUPPORT_RATIO or not sanitized:
            result["model_answer_rejected_by_claim_verifier"] = True
            result["model_answer_before_claim_verification"] = result.get("answer")
            result["answer"] = self._deterministic_answer(str(question), sources)
            result["mode"] = "deterministic"
            result["model"] = None
            reason = (
                f"claim_verifier_fallback: factual support ratio {ratio:.3f} "
                f"below minimum {self.MIN_FACTUAL_SUPPORT_RATIO:.2f}"
            )
            prior = result.get("provider_error")
            result["provider_error"] = f"{prior}; {reason}" if prior else reason
        else:
            result["model_answer_rejected_by_claim_verifier"] = False
            result["model_answer_before_claim_verification"] = result.get("answer")
            result["answer"] = sanitized

        return result


def install_base_patch() -> None:
    """Install v6 across dashboard and autonomous investigation consumers."""
    import app.web.dashboard as dashboard
    dashboard.CaseCopilot = CaseCopilot
    try:
        import app.forensics.autonomous_investigation as autonomous
        autonomous.CaseCopilot = CaseCopilot
    except Exception:
        pass


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
