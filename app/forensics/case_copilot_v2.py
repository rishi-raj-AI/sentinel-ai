from __future__ import annotations

import re

from app.forensics.case_copilot import CaseCopilot as BaseCaseCopilot, CopilotSource, ModelProvider


class CaseCopilot(BaseCaseCopilot):
    """Citation-hardened copilot with tolerant formatting normalization.

    Only source IDs already present in the retrieved Sentinel context may be
    normalized. Unknown Sentinel-looking IDs are intentionally left untouched so
    the grounding validator can reject the model answer.
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
    def _normalize_citations(cls, answer: str, sources: list[CopilotSource]) -> str:
        allowed = {source.source_id.upper(): source.source_id for source in sources}
        normalized = answer

        # Canonicalize backticked valid IDs first.
        for upper_id, canonical in sorted(allowed.items(), key=lambda item: len(item[0]), reverse=True):
            normalized = re.sub(
                rf"`\s*{re.escape(canonical)}\s*`",
                f"[{canonical}]",
                normalized,
                flags=re.IGNORECASE,
            )

        # Canonicalize valid IDs occurring outside an existing bracket group.
        bracket_ranges = [(m.start(), m.end()) for m in re.finditer(r"\[[^\[\]]+\]", normalized)]
        matches: list[tuple[int, int, str]] = []
        for match in cls.SOURCE_TOKEN_RE.finditer(normalized):
            token = match.group(0)
            canonical = allowed.get(token.upper())
            if not canonical:
                continue
            if any(start <= match.start() < end for start, end in bracket_ranges):
                continue
            matches.append((match.start(), match.end(), canonical))

        for start, end, canonical in reversed(matches):
            normalized = normalized[:start] + f"[{canonical}]" + normalized[end:]
        return normalized

    @classmethod
    def _citation_tokens(cls, answer: str) -> set[str]:
        tokens: set[str] = set()
        for bracket in re.findall(r"\[([^\[\]]+)\]", answer):
            cleaned = bracket.replace("`", " ")
            for match in cls.SOURCE_TOKEN_RE.findall(cleaned):
                tokens.add(match.upper())
        return tokens

    @classmethod
    def _unknown_sentinel_tokens(cls, answer: str, allowed: set[str]) -> set[str]:
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


def install_base_patch() -> None:
    BaseCaseCopilot.SOURCE_TOKEN_RE = CaseCopilot.SOURCE_TOKEN_RE
    BaseCaseCopilot._system_prompt = staticmethod(CaseCopilot._system_prompt)
    BaseCaseCopilot._user_prompt = staticmethod(CaseCopilot._user_prompt)
    BaseCaseCopilot._normalize_citations = classmethod(CaseCopilot._normalize_citations.__func__)
    BaseCaseCopilot._citation_tokens = classmethod(CaseCopilot._citation_tokens.__func__)
    BaseCaseCopilot._unknown_sentinel_tokens = classmethod(CaseCopilot._unknown_sentinel_tokens.__func__)
    BaseCaseCopilot._citations_are_grounded = classmethod(CaseCopilot._citations_are_grounded.__func__)


install_base_patch()

__all__ = ["CaseCopilot", "CopilotSource", "ModelProvider", "install_base_patch"]
