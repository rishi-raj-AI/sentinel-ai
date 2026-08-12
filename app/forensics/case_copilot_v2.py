from __future__ import annotations

import re

from app.forensics.case_copilot import CaseCopilot as BaseCaseCopilot, CopilotSource, ModelProvider


class CaseCopilot(BaseCaseCopilot):
    """Citation-hardened copilot with tolerant formatting normalization.

    The model is still restricted to retrieved Sentinel source IDs, but harmless
    formatting variants such as multiple IDs inside one bracket, backticks, or a
    leading ``Source:`` label no longer cause an unnecessary fallback.
    """

    SOURCE_PREFIXES = ("EVIDENCE", "SIGMA", "YARA", "FLOW", "TIMELINE", "ATTACK", "BRIEF")
    SOURCE_TOKEN_RE = re.compile(
        r"\b(?:EVIDENCE|SIGMA|YARA|FLOW|TIMELINE|ATTACK|BRIEF):[A-Za-z0-9_.:-]+\b",
        re.IGNORECASE,
    )

    @staticmethod
    def _system_prompt() -> str:
        return (
            "You are Sentinel's read-only forensic case copilot. Answer only from the supplied case sources. "
            "Do not invent facts, compromise verdicts, attribution, or missing telemetry. Distinguish observations from inference. "
            "Every material factual claim must cite at least one source from the ALLOWED SOURCE IDS list. "
            "Citation format must be square brackets containing one or more exact IDs, for example [FLOW:2] or "
            "[FLOW:2, EVIDENCE:E0003]. Never invent, shorten, rename, or alter an ID. "
            "If the sources are insufficient, say so. Keep answers concise and investigator-oriented."
        )

    @staticmethod
    def _user_prompt(question: str, sources: list[CopilotSource]) -> str:
        allowed = "\n".join(f"- {source.source_id}" for source in sources)
        rendered = "\n\n".join(
            f"SOURCE {source.source_id}\nKIND: {source.kind}\nTITLE: {source.title}\nTEXT: {source.text}"
            for source in sources
        )
        return (
            f"QUESTION:\n{question}\n\n"
            f"ALLOWED SOURCE IDS (copy these exactly when citing):\n{allowed}\n\n"
            f"CASE SOURCES:\n{rendered}"
        )

    @classmethod
    def _citation_tokens(cls, answer: str) -> set[str]:
        """Extract Sentinel source IDs only from square-bracket citation groups."""
        tokens: set[str] = set()
        for bracket in re.findall(r"\[([^\[\]]+)\]", answer):
            cleaned = bracket.replace("`", " ")
            for match in cls.SOURCE_TOKEN_RE.findall(cleaned):
                tokens.add(match.upper())
        return tokens

    @classmethod
    def _unknown_sentinel_tokens(cls, answer: str, allowed: set[str]) -> set[str]:
        """Detect invented Sentinel-looking IDs anywhere in the answer."""
        seen = {token.upper() for token in cls.SOURCE_TOKEN_RE.findall(answer)}
        return seen - allowed

    @classmethod
    def _citations_are_grounded(cls, answer: str, sources: list[CopilotSource]) -> bool:
        allowed = {source.source_id.upper() for source in sources}
        cited = cls._citation_tokens(answer)
        if not cited:
            return False
        if not cited.issubset(allowed):
            return False
        if cls._unknown_sentinel_tokens(answer, allowed):
            return False
        return True


__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider"]
