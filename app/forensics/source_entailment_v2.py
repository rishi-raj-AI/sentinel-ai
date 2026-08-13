from __future__ import annotations

from app.forensics.claim_verifier import ClaimVerification
from app.forensics.source_entailment import SourceAwareClaimVerifier as BaseVerifier


class SourceAwareClaimVerifier(BaseVerifier):
    @staticmethod
    def _has_structured_flow_facts(checks: list[dict]) -> bool:
        for check in checks:
            if check.get("source_id") != "FLOW:AGGREGATE" or not check.get("entailed"):
                continue
            detail = check.get("detail") or {}
            if any((detail.get("asserted_ips"), detail.get("asserted_ports"), detail.get("asserted_packet_counts"), detail.get("asserted_evidence_ids"), detail.get("low_packet_claimed"))):
                return True
        return False

    def verify_claim(self, claim: str) -> ClaimVerification:
        clean = self._strip_markdown(claim)
        claim_type = self._claim_type(clean)
        source_ids = self._source_ids(clean)
        cited = [self.sources[sid.upper()] for sid in source_ids if sid.upper() in self.sources]
        if claim_type in {"RECOMMENDATION", "LIMITATION"}:
            return ClaimVerification(clean, claim_type, source_ids, "SUPPORTED", 1.0, [])
        if not source_ids:
            return ClaimVerification(clean, claim_type, [], "UNSUPPORTED", 0.0, ["Factual claim has no Sentinel source citation."])
        if len(cited) != len(source_ids):
            return ClaimVerification(clean, claim_type, source_ids, "UNSUPPORTED", 0.0, ["One or more cited source IDs are unavailable to the verifier."])
        typed_ok, typed_reasons, checks = self._typed_entailment(clean, cited)
        guardrails = self._semantic_guardrails(clean, cited)
        score = self._support_score(clean, cited)
        reasons = list(dict.fromkeys(typed_reasons + guardrails))
        structured_support = typed_ok and self._has_structured_flow_facts(checks)
        threshold = 0.12 if claim_type == "INFERRED" else 0.20
        if typed_ok and not structured_support and score < threshold:
            reasons.append(f"Residual claim/source support {score:.3f} is below {threshold:.2f} sanity threshold.")
        status = "SUPPORTED" if not reasons else "UNSUPPORTED"
        return ClaimVerification(clean, claim_type, source_ids, status, score, reasons)

    def verify_answer(self, answer: str) -> dict:
        result = super().verify_answer(answer)
        result["policy"].update({
            "structured_fact_entailment_precedes_lexical_similarity": True,
            "lexical_overlap_used_only_without_structured_fact_support": True,
        })
        return result


__all__ = ["SourceAwareClaimVerifier"]
