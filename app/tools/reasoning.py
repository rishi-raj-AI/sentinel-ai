from __future__ import annotations

from app.forensics.case_manager import CaseManager
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.threat_intel import ThreatIntelEngine


def case_brief(case_id: str, max_items: int = 20, sigma_rules: str = "rules/sigma"):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return CaseReasoningEngine(case_dir, sigma_rules=sigma_rules).build(max_items=max_items)


def threat_intel_inventory(case_id: str, max_items: int = 200):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return ThreatIntelEngine(case_dir).inventory(max_items=max_items)
