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

            # Paths are reduced to the retrieved basename; aliases are never
            # generated from directory components.
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

        # Replace exact metadata-derived aliases only. Longest-first prevents a
        # shorter alias from consuming the prefix of a longer preserved name.
        for alias_folded, canonical in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_.:-]){re.escape(alias_folded)}(?![A-Za-z0-9_.:-])",
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
        _, provenance_repairs = cls._canonicalize_evidence_aliases(answer, sources)
        diagnostics["provenance_repairs_available"] = provenance_repairs
        diagnostics["evidence_alias_count"] = len(cls._evidence_aliases(sources))
        return diagnostics


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
