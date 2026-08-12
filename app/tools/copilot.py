from __future__ import annotations

from app.forensics.case_copilot_v3 import CaseCopilot, ModelProvider
from app.forensics.case_manager import CaseManager


def copilot_status():
    provider = ModelProvider()
    return {
        "configured": provider.configured,
        "mode": "model" if provider.configured else "deterministic",
        "model": provider.model or None,
        "endpoint_configured": bool(provider.endpoint),
        "config_source": provider.config_source,
        "transport": provider.transport,
        "active_endpoint": provider.active_endpoint,
        "grounding": "case-retrieval-required",
    }


def copilot_ask(case_id: str, question: str, max_sources: int = 12):
    manager = CaseManager()
    manager.load_case(case_id)
    case_dir = manager.root / case_id
    return CaseCopilot(case_dir).answer(question, max_sources=max_sources)
