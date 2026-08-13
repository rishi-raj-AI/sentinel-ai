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
    A malformed evidence citation may be repaired only when its suffix can be
    derived exactly from filename metadata on the same retrieved evidence
    source. Arbitrary evidence/filename combinations remain invalid.
    """

    EVIDENCE_ALIAS_RE = re.compile(r"\bEVIDENCE:(E\d{4,})_([A-Za-z0-9_.() -]+)", re.IGNORECASE)

    @staticmethod
    def _norm_filename(value: str) -> str:
        # Case-insensitive filesystem-style comparison while preserving only the
        # filename token itself; paths are never accepted as evidence aliases.
        return value.strip().replace("\\", "/").rsplit("/", 1)[-1].casefold()

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
            # Two model mistakes are safe to canonicalize because both are
            # derived entirely from the retrieved evidence record:
            #   EVIDENCE:E0004_yara-test-artifact.txt
            #   EVIDENCE:E0004_yara-test-artifact.txt when filename already
            #   contains the E0004_ preservation prefix.
            candidate_suffixes = {basename}
            prefix = f"{evidence_id}_"
            if basename.casefold().startswith(prefix.casefold()):
                candidate_suffixes.add(basename[len(prefix):])

            for suffix in candidate_suffixes:
                alias = f"EVIDENCE:{evidence_id}_{suffix}".casefold()
                aliases[alias] = source.source_id
        return aliases

    @classmethod
    def _canonicalize_evidence_aliases(
        cls, answer: str, sources: list[CopilotSource]
    ) -> tuple[str, list[dict[str, str]]]:
        aliases = cls._evidence_aliases(sources)
        repairs: list[dict[str, str]] = []
        if not aliases:
            return answer, repairs

        def replace(match: re.Match[str]) -> str:
            raw = match.group(0)
            canonical = aliases.get(raw.casefold())
            if not canonical:
                return raw
            repairs.append({
                "original": raw,
                "canonical": canonical,
                "basis": "retrieved_evidence_filename_metadata",
            })
            return canonical

        return cls.EVIDENCE_ALIAS_RE.sub(replace, answer), repairs

    @classmethod
    def _normalize_citations(cls, answer: str, sources: list[CopilotSource]) -> str:
        # First collapse only metadata-proven evidence aliases, then let the v2
        # canonicalizer add square brackets around retrieved source IDs.
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
