from __future__ import annotations

from dataclasses import asdict
from typing import Any

from app.forensics.case_copilot_v3 import CaseCopilot as TransportCaseCopilot, CopilotSource, ModelProvider


class CaseCopilot(TransportCaseCopilot):
    """Grounded copilot with one constrained citation-repair pass.

    If a model draft fails grounding only because citations are missing or
    malformed, Sentinel asks the same model once to rewrite that draft using the
    exact retrieved source IDs. Unknown/invented Sentinel IDs never qualify for
    repair and still trigger deterministic fallback.
    """

    @classmethod
    def _diagnostics(cls, answer: str, sources: list[CopilotSource]) -> dict[str, Any]:
        allowed = {source.source_id.upper() for source in sources}
        cited = cls._citation_tokens(answer)
        unknown = cls._unknown_sentinel_tokens(answer, allowed)
        seen = {token.upper() for token in cls.SOURCE_TOKEN_RE.findall(answer)}
        return {
            "allowed_source_ids": sorted(source.source_id for source in sources),
            "cited_source_ids": sorted(cited),
            "seen_sentinel_ids": sorted(seen),
            "unknown_source_ids": sorted(unknown),
            "has_valid_citation": bool(cited and cited.issubset(allowed)),
        }

    @staticmethod
    def _repair_prompt(question: str, draft: str, sources: list[CopilotSource]) -> str:
        allowed = "\n".join(f"- {source.source_id}" for source in sources)
        rendered = "\n\n".join(
            f"SOURCE {source.source_id}\nTITLE: {source.title}\nTEXT: {source.text}"
            for source in sources
        )
        return (
            "Repair citations in the draft below. Do not add new factual claims. "
            "Keep only claims supported by the supplied sources. Every material factual claim must cite one or more exact IDs "
            "from ALLOWED SOURCE IDS in square brackets. Never invent or modify an ID.\n\n"
            f"QUESTION:\n{question}\n\n"
            f"DRAFT TO REPAIR:\n{draft}\n\n"
            f"ALLOWED SOURCE IDS:\n{allowed}\n\n"
            f"CASE SOURCES:\n{rendered}"
        )

    def answer(self, question: str, *, max_sources: int = 12) -> dict[str, Any]:
        text = question.strip()
        if not text:
            return {
                "answer": "Ask a question about the current case.",
                "sources": [],
                "mode": "none",
                "model": None,
                "citation_repair_attempted": False,
            }

        sources = self.retrieve(text, limit=max_sources)
        mode = "deterministic"
        model_name: str | None = None
        error: str | None = None
        raw_model_answer: str | None = None
        normalized_model_answer: str | None = None
        repaired_model_answer: str | None = None
        repair_attempted = False
        initial_diagnostics: dict[str, Any] | None = None
        final_diagnostics: dict[str, Any] | None = None

        if self.provider.configured:
            try:
                raw_model_answer = self.provider.complete(self._system_prompt(), self._user_prompt(text, sources))
                normalized_model_answer = self._normalize_citations(raw_model_answer, sources)
                initial_diagnostics = self._diagnostics(normalized_model_answer, sources)

                answer = normalized_model_answer
                if not self._citations_are_grounded(answer, sources):
                    if initial_diagnostics.get("unknown_source_ids"):
                        raise RuntimeError(
                            "Model answer referenced unknown Sentinel source IDs: "
                            + ", ".join(initial_diagnostics["unknown_source_ids"])
                        )
                    repair_attempted = True
                    repaired_model_answer = self.provider.complete(
                        self._system_prompt(),
                        self._repair_prompt(text, normalized_model_answer, sources),
                    )
                    answer = self._normalize_citations(repaired_model_answer, sources)
                    final_diagnostics = self._diagnostics(answer, sources)
                    if not self._citations_are_grounded(answer, sources):
                        raise RuntimeError("Citation repair did not produce only valid retrieved Sentinel citations")
                else:
                    final_diagnostics = initial_diagnostics

                mode = "model"
                model_name = self.provider.model
            except Exception as exc:
                error = f"model_fallback: {type(exc).__name__}: {exc}"
                answer = self._deterministic_answer(text, sources)
        else:
            answer = self._deterministic_answer(text, sources)

        result = {
            "answer": answer,
            "mode": mode,
            "model": model_name,
            "sources": [asdict(source) for source in sources],
            "source_count": len(sources),
            "provider_error": error,
            "grounding": "Answer constrained to retrieved Sentinel case sources.",
            "raw_model_answer": raw_model_answer,
            "normalized_model_answer": normalized_model_answer,
            "repaired_model_answer": repaired_model_answer,
            "citation_repair_attempted": repair_attempted,
            "citation_diagnostics_initial": initial_diagnostics,
            "citation_diagnostics_final": final_diagnostics,
            "configured_model": getattr(self.provider, "configured_model", getattr(self.provider, "model", None)),
            "persisted_model": getattr(self.provider, "persisted_model", None),
            "transport": getattr(self.provider, "transport", None),
            "active_endpoint": getattr(self.provider, "active_endpoint", None),
            "resolved_model": getattr(self.provider, "resolved_model", None),
        }
        if result.get("mode") == "model":
            result["model"] = getattr(self.provider, "model", result.get("model"))
        return result


def install_base_patch() -> None:
    import app.web.dashboard as dashboard
    dashboard.CaseCopilot = CaseCopilot
    try:
        import app.forensics.autonomous_investigation as autonomous
        autonomous.CaseCopilot = CaseCopilot
    except Exception:
        pass


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
