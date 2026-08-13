from __future__ import annotations

import json
import re
from typing import Any

from app.forensics.case_copilot_v4 import (
    CaseCopilot as RepairCaseCopilot,
    CopilotSource,
    ModelProvider,
)


class CaseCopilot(RepairCaseCopilot):
    """Provenance-aware grounded copilot.

    Extends citation repair with metadata-bound evidence alias canonicalization
    and section-aware BRIEF aliases. A malformed citation is repaired only when
    its alias can be derived from the retrieved source itself.
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
                if suffix:
                    aliases[f"EVIDENCE:{evidence_id}_{suffix}".casefold()] = source.source_id
        return aliases

    @classmethod
    def _brief_aliases(cls, sources: list[CopilotSource]) -> dict[str, str]:
        """Build section aliases only from keys actually present in a retrieved brief."""
        aliases: dict[str, str] = {}
        for source in sources:
            if source.kind != "brief" or source.source_id.upper() != "BRIEF:CURRENT":
                continue
            try:
                payload = json.loads(source.text)
            except (TypeError, json.JSONDecodeError):
                payload = {}
            if not isinstance(payload, dict):
                continue
            for key, value in payload.items():
                if value in (None, "", [], {}):
                    continue
                section = re.sub(r"[^A-Za-z0-9]+", "_", str(key)).strip("_").upper()
                if section:
                    aliases[f"BRIEF:CURRENT:{section}".casefold()] = source.source_id
        return aliases

    @classmethod
    def _canonicalize_alias_map(
        cls,
        answer: str,
        aliases: dict[str, str],
        *,
        basis: str,
    ) -> tuple[str, list[dict[str, str]]]:
        repairs: list[dict[str, str]] = []
        normalized = answer
        for alias_folded, canonical in sorted(aliases.items(), key=lambda item: len(item[0]), reverse=True):
            pattern = re.compile(
                rf"(?<![A-Za-z0-9_:-]){re.escape(alias_folded)}(?![A-Za-z0-9_:-])",
                re.IGNORECASE,
            )

            def replace(match: re.Match[str], canonical_id: str = canonical) -> str:
                raw = match.group(0)
                repairs.append({"original": raw, "canonical": canonical_id, "basis": basis})
                return canonical_id

            normalized = pattern.sub(replace, normalized)
        return normalized, repairs

    @classmethod
    def _canonicalize_evidence_aliases(
        cls, answer: str, sources: list[CopilotSource]
    ) -> tuple[str, list[dict[str, str]]]:
        return cls._canonicalize_alias_map(
            answer,
            cls._evidence_aliases(sources),
            basis="retrieved_evidence_filename_metadata",
        )

    @classmethod
    def _canonicalize_brief_aliases(
        cls, answer: str, sources: list[CopilotSource]
    ) -> tuple[str, list[dict[str, str]]]:
        return cls._canonicalize_alias_map(
            answer,
            cls._brief_aliases(sources),
            basis="retrieved_brief_section_metadata",
        )

    @classmethod
    def _canonicalize_provenance_aliases(
        cls, answer: str, sources: list[CopilotSource]
    ) -> tuple[str, list[dict[str, str]], list[dict[str, str]]]:
        evidence_normalized, evidence_repairs = cls._canonicalize_evidence_aliases(answer, sources)
        normalized, brief_repairs = cls._canonicalize_brief_aliases(evidence_normalized, sources)
        return normalized, evidence_repairs, brief_repairs

    @classmethod
    def _normalize_citations(cls, answer: str, sources: list[CopilotSource]) -> str:
        canonicalized, _, _ = cls._canonicalize_provenance_aliases(answer, sources)
        return super()._normalize_citations(canonicalized, sources)

    @classmethod
    def _diagnostics(cls, answer: str, sources: list[CopilotSource]) -> dict[str, Any]:
        diagnostics = super()._diagnostics(answer, sources)
        diagnostics["evidence_alias_count"] = len(cls._evidence_aliases(sources))
        diagnostics["brief_section_alias_count"] = len(cls._brief_aliases(sources))
        return diagnostics

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        result = super().answer(question, max_sources=max_sources)
        sources = [CopilotSource(**source) if isinstance(source, dict) else source for source in result.get("sources", [])]

        initial_raw = result.get("raw_model_answer") or ""
        repaired_raw = result.get("repaired_model_answer") or ""
        _, initial_evidence, initial_brief = self._canonicalize_provenance_aliases(initial_raw, sources)
        _, repair_evidence, repair_brief = self._canonicalize_provenance_aliases(repaired_raw, sources)

        result["provenance_repairs_initial"] = initial_evidence
        result["provenance_repairs_repair_pass"] = repair_evidence
        result["brief_section_repairs_initial"] = initial_brief
        result["brief_section_repairs_repair_pass"] = repair_brief
        result["provenance_repair_count"] = len(initial_evidence) + len(repair_evidence) + len(initial_brief) + len(repair_brief)
        result["grounding_policy"] = {
            "unknown_source_ids_rejected": True,
            "metadata_bound_aliases_only": True,
            "brief_section_aliases_require_retrieved_nonempty_sections": True,
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
