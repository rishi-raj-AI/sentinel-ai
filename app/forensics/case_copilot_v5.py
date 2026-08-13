from __future__ import annotations

import re
from typing import Any

from app.forensics.case_copilot_v4 import (
    CaseCopilot as RepairCaseCopilot,
    CopilotSource,
    ModelProvider,
)


class CaseCopilot(RepairCaseCopilot):
    """Provenance-aware grounded copilot.

    Extends citation repair with metadata-bound evidence alias canonicalization.
    A malformed evidence citation may be repaired only when it exactly matches
    an alias derived from filename metadata on the same retrieved evidence
    source. Arbitrary evidence/filename combinations remain invalid.
    """

    @classmethod
    def _evidence_aliases(cls, sources: list[CopilotSource]) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for source in sources:
            if source.kind != "evidence" or not source.source_id.upper().startswith("EVIDENCE:"):
                continue
            evidence_id = source.source_id.split(":", 1)[1]
            metadata = source.metadata or {}
            filename = str(metadata.get("filename") or "").strip()
            if not filename:
                continue

            basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
            candidate_suffixes = {basename}
            preservation_prefix = f"{evidence_id}_"
            if basename.casefold().startswith(preservation_prefix.casefold()):
                candidate_suffixes.add(basename[len(preservation_prefix):])

            for suffix in candidate_suffixes:
                if not suffix:
                    continue
                aliases[f"EVIDENCE:{evidence_id}_{suffix}".casefold()] = source.source_id
        return aliases

    @classmethod
    def _canonicalize_evidence_aliases(
        cls, answer: str, sources: list[CopilotSource]
    ) -> tuple[str, list[dict[str, str]]]:
        aliases = cls._evidence_aliases(sources)
        repairs: list[dict[str, str]] = []
        normalized = answer

        for alias_folded, canonical in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
            # A sentence-ending period must not be treated as part of the alias.
            # Dots remain legal inside the metadata-derived filename itself.
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_:-]){re.escape(alias_folded)}(?![A-Za-z0-9_:-])",
                re.IGNORECASE,
            )

            def replace(match: re.Match[str], canonical_id: str = canonical) -> str:
                raw = match.group(0)
                repairs.append({
                    "original": raw,
                    "canonical": canonical_id,
                    "basis": "retrieved_evidence_filename_metadata",
                })
                return canonical_id

            normalized = pattern.sub(replace, normalized)

        return normalized, repairs

    @classmethod
    def _normalize_citations(cls, answer: str, sources: list[CopilotSource]) -> str:
        canonicalized, _ = cls._canonicalize_evidence_aliases(answer, sources)
        return super()._normalize_citations(canonicalized, sources)

    @classmethod
    def _diagnostics(cls, answer: str, sources: list[CopilotSource]) -> dict[str, Any]:
        diagnostics = super()._diagnostics(answer, sources)
        diagnostics["evidence_alias_count"] = len(cls._evidence_aliases(sources))
        return diagnostics

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        result = super().answer(question, max_sources=max_sources)
        sources = [
            CopilotSource(**source) if isinstance(source, dict) else source
            for source in result.get("sources", [])
        ]

        initial_raw = result.get("raw_model_answer")
        repaired_raw = result.get("repaired_model_answer")
        _, initial_repairs = self._canonicalize_evidence_aliases(initial_raw or "", sources)
        _, repair_pass_repairs = self._canonicalize_evidence_aliases(repaired_raw or "", sources)

        result["provenance_repairs_initial"] = initial_repairs
        result["provenance_repairs_repair_pass"] = repair_pass_repairs
        result["provenance_repair_count"] = len(initial_repairs) + len(repair_pass_repairs)
        result["grounding_policy"] = {
            "unknown_source_ids_rejected": True,
            "metadata_bound_aliases_only": True,
            "provenance_repairs_audited": True,
        }
        return result


def install_base_patch() -> None:
    """Install v5 consistently across CLI/dashboard/autonomous consumers."""
    import app.web.dashboard as dashboard
    dashboard.CaseCopilot = CaseCopilot
    try:
        import app.forensics.autonomous_investigation as autonomous
        autonomous.CaseCopilot = CaseCopilot
    except Exception:
        pass


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
