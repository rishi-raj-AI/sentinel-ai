from __future__ import annotations

from app.forensics.case_manager import CaseManager
from app.forensics.sigma_engine import SigmaEngine


def sigma_analyze(case_id: str, rule_path: str, max_detections: int = 100):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return SigmaEngine(case_dir).analyze(rule_path, max_detections=max_detections)
