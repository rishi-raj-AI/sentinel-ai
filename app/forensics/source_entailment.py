from __future__ import annotations

import re
from typing import Any, Iterable

from app.forensics.case_copilot import CopilotSource
from app.forensics.claim_verifier import ClaimEvidenceVerifier, ClaimVerification


class SourceAwareClaimVerifier(ClaimEvidenceVerifier):
    """Claim verifier that reasons about what each Sentinel source type can prove.

    Lexical overlap remains a weak fallback signal only. Structured source
    semantics are checked first so a timeline row cannot prove normality, a
    network flow cannot prove malware, and a Sigma/YARA hit cannot be promoted
    into a compromise verdict without explicit supporting metadata.
    """

    NORMALITY_TERMS = (
        "normal system activity", "normal activity", "benign activity", "legitimate activity",
        "expected activity", "harmless", "safe activity",
    )
    MALICIOUSNESS_TERMS = (
        "malware", "malicious", "compromise", "infected", "command-and-control", "c2",
        "persistence", "lateral movement", "credential theft",
    )
    CITATION_ONLY_RE = re.compile(
        r"^\s*\[(?:\s*(?:EVIDENCE|SIGMA|YARA|FLOW|TIMELINE|ATTACK|BRIEF):[^\[\],]+\s*,?\s*)+\]\s*$",
        re.IGNORECASE,
    )

    def __init__(self, sources: Iterable[CopilotSource | dict[str, Any]]) -> None:
        super().__init__(sources)

    @staticmethod
    def _metadata_blob(source: CopilotSource) -> str:
        return f"{source.title} {source.text} {source.metadata or {}}".casefold()

    @classmethod
    def _contains_any(cls, text: str, terms: tuple[str, ...]) -> bool:
        lower = text.casefold()
        return any(term in lower for term in terms)

    @classmethod
    def _attach_adjacent_citations(cls, answer: str) -> tuple[str, int]:
        """Attach citation-only lines to the preceding factual line.

        Local models commonly emit a claim and put `[FLOW:1]` on the next line.
        Treating that as two claims unfairly marks the sentence uncited and the
        citation as a standalone fact. We merge only citation-only lines into a
        preceding non-heading, non-empty line that does not already contain a
        Sentinel citation.
        """
        lines = answer.splitlines()
        merged: list[str] = []
        bindings = 0
        for raw in lines:
            stripped = raw.strip()
            if cls.CITATION_ONLY_RE.fullmatch(stripped) and merged:
                idx = len(merged) - 1
                while idx >= 0 and not merged[idx].strip():
                    idx -= 1
                if idx >= 0:
                    previous = merged[idx].strip()
                    is_heading = previous.startswith("#") or (
                        previous.startswith("**") and previous.endswith("**") and len(previous) < 100
                    )
                    already_cited = bool(cls._source_ids(previous))
                    if previous and not is_heading and not already_cited:
                        merged[idx] = merged[idx].rstrip() + " " + stripped
                        bindings += 1
                        continue
            merged.append(raw)
        return "\n".join(merged), bindings

    def _timeline_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        reasons: list[str] = []
        if self._contains_any(lower, self.NORMALITY_TERMS):
            reasons.append("Timeline occurrence proves an event was logged, not that the activity was normal or benign.")
        if self._contains_any(lower, self.MALICIOUSNESS_TERMS) and not self._contains_any(blob, self.MALICIOUSNESS_TERMS):
            reasons.append("Timeline source does not contain telemetry establishing the claimed malicious behavior.")
        return (not reasons, reasons)

    def _flow_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        reasons: list[str] = []
        if self._contains_any(lower, self.MALICIOUSNESS_TERMS) and not self._contains_any(blob, self.MALICIOUSNESS_TERMS):
            reasons.append("Network-flow telemetry can establish endpoints/protocol/ports, but does not by itself establish malware or compromise.")
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", claim):
            if ip.casefold() not in blob:
                reasons.append(f"Claimed IP {ip} is not present in the cited flow source.")
        for port in re.findall(r":(\d{1,5})\b", claim):
            if port not in blob:
                reasons.append(f"Claimed port {port} is not present in the cited flow source.")
        return (not reasons, reasons)

    def _sigma_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        metadata = source.metadata or {}
        reasons: list[str] = []
        if "malware-specific" in lower:
            tags = " ".join(str(x) for x in (metadata.get("tags") or [])).casefold()
            if "malware" not in tags:
                reasons.append("Sigma metadata does not identify this rule as malware-specific.")
        if any(term in lower for term in ("confirmed malware", "confirmed compromise", "definitely malicious", "is infected")):
            reasons.append("A Sigma detection alone cannot establish a definitive compromise verdict.")
        level = str(metadata.get("level") or "").casefold()
        if "high confidence" in lower and level not in {"high", "critical"}:
            reasons.append("Claimed high confidence is inconsistent with Sigma rule severity metadata.")
        if "medium" in lower and level and level != "medium" and "medium" not in blob:
            reasons.append("Claimed medium level is inconsistent with Sigma source metadata.")
        return (not reasons, reasons)

    def _yara_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        metadata = source.metadata or {}
        reasons: list[str] = []
        if any(term in lower for term in ("malware signature", "malware-specific", "confirms malware", "infected")):
            rule = str(metadata.get("rule") or source.title or "").casefold()
            if "malware" not in rule and "malware" not in blob:
                reasons.append("YARA match does not establish that the rule is malware-specific.")
        m = re.search(r"matched .*?\b(\d+)\s+times?\b", lower)
        if m:
            expected = str(metadata.get("match_count") or "")
            if expected and m.group(1) != expected:
                reasons.append("Claimed YARA match count does not match source metadata.")
        return (not reasons, reasons)

    def _evidence_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        reasons: list[str] = []
        if self._contains_any(lower, self.MALICIOUSNESS_TERMS) and not self._contains_any(blob, self.MALICIOUSNESS_TERMS):
            reasons.append("Evidence registration metadata proves identity/integrity, not maliciousness.")
        sha_values = re.findall(r"\b[a-f0-9]{64}\b", lower)
        for value in sha_values:
            if value not in blob:
                reasons.append("Claimed SHA-256 is not present in the cited evidence metadata.")
        return (not reasons, reasons)

    def _attack_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        reasons: list[str] = []
        for technique in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", claim, flags=re.I):
            if technique.casefold() not in blob:
                reasons.append(f"Claimed ATT&CK technique {technique} is not present in the cited source.")
        if any(term in lower for term in ("confirmed compromise", "definitely malicious", "is infected")):
            reasons.append("ATT&CK mapping is behavioral categorization, not proof of compromise.")
        return (not reasons, reasons)

    def _brief_entailment(self, claim: str, source: CopilotSource) -> tuple[bool, list[str]]:
        lower = claim.casefold()
        blob = self._metadata_blob(source)
        reasons: list[str] = []
        if "high confidence" in lower and "high" not in blob:
            reasons.append("Claim escalates confidence beyond the retrieved case brief.")
        return (not reasons, reasons)

    def _typed_entailment(self, claim: str, cited: list[CopilotSource]) -> tuple[bool, list[str], list[dict[str, Any]]]:
        reasons: list[str] = []
        checks: list[dict[str, Any]] = []
        for source in cited:
            kind = source.kind.casefold()
            if kind == "timeline":
                ok, source_reasons = self._timeline_entailment(claim, source)
            elif kind == "network":
                ok, source_reasons = self._flow_entailment(claim, source)
            elif kind == "sigma":
                ok, source_reasons = self._sigma_entailment(claim, source)
            elif kind == "yara":
                ok, source_reasons = self._yara_entailment(claim, source)
            elif kind == "evidence":
                ok, source_reasons = self._evidence_entailment(claim, source)
            elif kind == "attack":
                ok, source_reasons = self._attack_entailment(claim, source)
            elif kind == "brief":
                ok, source_reasons = self._brief_entailment(claim, source)
            else:
                ok, source_reasons = True, []
            checks.append({
                "source_id": source.source_id,
                "source_kind": source.kind,
                "entailed": ok,
                "reasons": source_reasons,
            })
            reasons.extend(source_reasons)
        return (not reasons, reasons, checks)

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

        typed_ok, typed_reasons, _ = self._typed_entailment(clean, cited)
        guardrails = self._semantic_guardrails(clean, cited)
        score = self._support_score(clean, cited)

        reasons = list(dict.fromkeys(typed_reasons + guardrails))
        threshold = 0.12 if claim_type == "INFERRED" else 0.20
        if typed_ok and score < threshold:
            reasons.append(f"Residual claim/source support {score:.3f} is below {threshold:.2f} sanity threshold.")

        status = "SUPPORTED" if not reasons else "UNSUPPORTED"
        return ClaimVerification(clean, claim_type, source_ids, status, score, reasons)

    def verify_answer(self, answer: str) -> dict[str, Any]:
        bound_answer, binding_count = self._attach_adjacent_citations(answer)
        result = super().verify_answer(bound_answer)
        typed_checks: list[dict[str, Any]] = []
        for row in result.get("claims", []):
            source_ids = row.get("source_ids") or []
            cited = [self.sources[sid.upper()] for sid in source_ids if sid.upper() in self.sources]
            if row.get("claim_type") in {"OBSERVED", "INFERRED"} and cited:
                _, _, checks = self._typed_entailment(str(row.get("claim") or ""), cited)
                typed_checks.append({"claim": row.get("claim"), "checks": checks})
        result["source_type_entailment"] = typed_checks
        result["adjacent_citation_bindings"] = binding_count
        result["policy"].update({
            "source_type_aware_entailment": True,
            "lexical_overlap_secondary_only": True,
            "timeline_occurrence_does_not_imply_normality": True,
            "detections_do_not_imply_compromise": True,
            "adjacent_citation_lines_bound": True,
        })
        return result


__all__ = ["SourceAwareClaimVerifier"]
