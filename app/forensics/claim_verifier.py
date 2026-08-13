from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Any, Iterable

from app.forensics.case_copilot import CopilotSource


@dataclass(slots=True)
class ClaimVerification:
    claim: str
    claim_type: str
    source_ids: list[str]
    status: str
    support_score: float
    reasons: list[str]


class ClaimEvidenceVerifier:
    """Deterministic claim-level verifier for grounded forensic prose.

    Citation validation proves a referenced source exists. This verifier checks a
    stronger property: whether the text of a factual claim is plausibly supported
    by the cited Sentinel source(s). Recommendations and explicit limitations are
    allowed without evidentiary entailment, while observations and inferences must
    have cited support. Unsupported factual claims are removed from the final
    investigator-facing answer and retained in the verification audit trail.
    """

    SOURCE_TOKEN_RE = re.compile(
        r"\b(?:EVIDENCE|SIGMA|YARA|FLOW|TIMELINE|ATTACK|BRIEF):[A-Za-z0-9_.:-]+\b",
        re.IGNORECASE,
    )
    BRACKET_RE = re.compile(r"\[([^\[\]]+)\]")
    WORD_RE = re.compile(r"[A-Za-z0-9_.:-]{3,}")

    STOPWORDS = {
        "the", "and", "that", "this", "with", "from", "into", "were", "was", "are", "for", "has", "have",
        "had", "been", "being", "but", "not", "only", "than", "then", "also", "each", "such", "these", "those",
        "system", "case", "evidence", "investigation", "investigator", "activity", "information", "data", "current",
        "detected", "review", "supported", "finding", "findings", "source", "sources", "rule", "rules",
    }

    RECOMMENDATION_PREFIXES = (
        "acquire ", "collect ", "review ", "validate ", "verify ", "identify ", "correlate ", "continue ", "run ",
        "consider ", "inspect ", "preserve ", "obtain ", "check ", "compare ", "determine ",
    )
    INFERENCE_MARKERS = (
        " may ", " might ", " could ", " suggests ", " suggest ", " consistent with ", " possibly ", " likely ",
        " potentially ", " indicates ", " indicate ", " appears ", " would be consistent ",
    )
    LIMITATION_MARKERS = (
        "lack of ", "no successfully ", "insufficient ", "limited telemetry", "not enough ", "cannot determine",
        "does not prove", "not proof", "absence of ", "limitation", "unknown ",
    )

    def __init__(self, sources: Iterable[CopilotSource | dict[str, Any]]) -> None:
        self.sources: dict[str, CopilotSource] = {}
        for row in sources:
            source = CopilotSource(**row) if isinstance(row, dict) else row
            self.sources[source.source_id.upper()] = source

    @classmethod
    def _strip_markdown(cls, text: str) -> str:
        value = re.sub(r"^\s*(?:[-*]|\d+\.)\s+", "", text.strip())
        value = re.sub(r"\*\*([^*]+)\*\*", r"\1", value)
        value = re.sub(r"`([^`]+)`", r"\1", value)
        return value.strip()

    @classmethod
    def _claim_type(cls, claim: str) -> str:
        lower = f" {claim.lower().strip()} "
        stripped = claim.lower().strip()
        if any(stripped.startswith(prefix) for prefix in cls.RECOMMENDATION_PREFIXES):
            return "RECOMMENDATION"
        if any(marker in lower for marker in cls.LIMITATION_MARKERS):
            return "LIMITATION"
        if any(marker in lower for marker in cls.INFERENCE_MARKERS):
            return "INFERRED"
        return "OBSERVED"

    @classmethod
    def _source_ids(cls, claim: str) -> list[str]:
        ids: list[str] = []
        for bracket in cls.BRACKET_RE.findall(claim):
            ids.extend(cls.SOURCE_TOKEN_RE.findall(bracket))
        return list(dict.fromkeys(ids))

    @classmethod
    def _tokens(cls, text: str) -> set[str]:
        return {
            token.casefold()
            for token in cls.WORD_RE.findall(text)
            if token.casefold() not in cls.STOPWORDS and not token.upper().startswith(("FLOW:", "SIGMA:", "YARA:", "EVIDENCE:", "TIMELINE:", "ATTACK:", "BRIEF:"))
        }

    @staticmethod
    def _source_blob(source: CopilotSource) -> str:
        metadata = source.metadata or {}
        return f"{source.title} {source.text} {metadata}".casefold()

    def _semantic_guardrails(self, claim: str, cited: list[CopilotSource]) -> list[str]:
        lower = claim.casefold()
        reasons: list[str] = []

        # Prevent common forensic overclaims seen in model output.
        if "malware-specific" in lower:
            tags = " ".join(
                str((source.metadata or {}).get("tags") or "")
                for source in cited
                if source.kind == "sigma"
            ).casefold()
            if "malware" not in tags:
                reasons.append("Claim labels a detection malware-specific without malware-specific source metadata.")

        if ("updated with" in lower or "recently scanned" in lower) and any(source.kind == "yara" for source in cited):
            combined = " ".join(self._source_blob(source) for source in cited)
            if "updated" not in combined and "scan" not in combined:
                reasons.append("YARA match timing does not establish that a system or rule was updated/scanned.")

        if any(term in lower for term in ("confirmed malware", "confirmed compromise", "definitely malicious", "is infected")):
            if not any(source.kind == "brief" and "high-confidence" in self._source_blob(source) for source in cited):
                reasons.append("Definitive compromise language is not supported by the retrieved case assessment.")

        return reasons

    def _support_score(self, claim: str, cited: list[CopilotSource]) -> float:
        claim_tokens = self._tokens(self.BRACKET_RE.sub("", claim))
        if not claim_tokens:
            return 1.0
        source_tokens: set[str] = set()
        for source in cited:
            source_tokens |= self._tokens(self._source_blob(source))
        overlap = claim_tokens & source_tokens
        return round(len(overlap) / max(1, len(claim_tokens)), 3)

    def verify_claim(self, claim: str) -> ClaimVerification:
        clean = self._strip_markdown(claim)
        claim_type = self._claim_type(clean)
        source_ids = self._source_ids(clean)
        cited = [self.sources[sid.upper()] for sid in source_ids if sid.upper() in self.sources]
        reasons: list[str] = []

        if claim_type in {"RECOMMENDATION", "LIMITATION"}:
            return ClaimVerification(clean, claim_type, source_ids, "SUPPORTED", 1.0, [])

        if not source_ids:
            return ClaimVerification(clean, claim_type, [], "UNSUPPORTED", 0.0, ["Factual claim has no Sentinel source citation."])
        if len(cited) != len(source_ids):
            reasons.append("One or more cited source IDs are unavailable to the verifier.")

        guardrails = self._semantic_guardrails(clean, cited)
        reasons.extend(guardrails)
        score = self._support_score(clean, cited)

        # Inference may use looser lexical overlap but must explicitly remain
        # probabilistic. Observations require stronger direct overlap.
        threshold = 0.18 if claim_type == "INFERRED" else 0.28
        if score < threshold:
            reasons.append(f"Claim/source lexical support {score:.3f} is below {threshold:.2f} threshold.")

        status = "SUPPORTED" if not reasons else "UNSUPPORTED"
        return ClaimVerification(clean, claim_type, source_ids, status, score, reasons)

    @classmethod
    def _candidate_lines(cls, answer: str) -> list[tuple[str, bool]]:
        rows: list[tuple[str, bool]] = []
        for raw in answer.splitlines():
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped:
                rows.append((line, False))
                continue
            # Headings are structure, not factual claims.
            if stripped.startswith("#") or (stripped.startswith("**") and stripped.endswith("**") and len(stripped) < 100):
                rows.append((line, False))
                continue
            rows.append((line, True))
        return rows

    def verify_answer(self, answer: str) -> dict[str, Any]:
        claims: list[ClaimVerification] = []
        output_lines: list[str] = []
        removed: list[str] = []

        for line, is_claim in self._candidate_lines(answer):
            if not is_claim:
                output_lines.append(line)
                continue
            verification = self.verify_claim(line)
            claims.append(verification)
            if verification.status == "SUPPORTED":
                output_lines.append(line)
            else:
                removed.append(line)

        sanitized = "\n".join(output_lines)
        sanitized = re.sub(r"\n{3,}", "\n\n", sanitized).strip()
        supported = sum(1 for claim in claims if claim.status == "SUPPORTED")
        unsupported = len(claims) - supported
        factual = [claim for claim in claims if claim.claim_type in {"OBSERVED", "INFERRED"}]
        factual_supported = sum(1 for claim in factual if claim.status == "SUPPORTED")
        factual_ratio = factual_supported / max(1, len(factual))

        return {
            "answer": sanitized,
            "claims": [asdict(claim) for claim in claims],
            "claim_count": len(claims),
            "supported_claim_count": supported,
            "unsupported_claim_count": unsupported,
            "removed_claims": removed,
            "factual_claim_support_ratio": round(factual_ratio, 3),
            "all_factual_claims_supported": factual_supported == len(factual),
            "policy": {
                "observed_requires_cited_support": True,
                "inference_requires_cited_support": True,
                "recommendations_allowed_without_entailment": True,
                "unsupported_claims_removed": True,
                "definitive_compromise_overclaims_guarded": True,
            },
        }
