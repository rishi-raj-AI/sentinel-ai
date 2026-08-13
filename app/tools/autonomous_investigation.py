from __future__ import annotations

from app.forensics.case_copilot_v4 import install_base_patch

install_base_patch()

from app.forensics.autonomous_investigation import AutonomousInvestigationAgent
from app.forensics.case_manager import CaseManager


def autonomous_investigate(case_id: str, objective: str, max_items: int = 25):
    manager = CaseManager()
    manager.load_case(case_id)
    case_dir = manager.root / case_id
    return AutonomousInvestigationAgent(case_dir).run(objective, max_items=max_items, persist=True)


def list_investigation_runs(case_id: str):
    manager = CaseManager()
    manager.load_case(case_id)
    case_dir = manager.root / case_id
    return AutonomousInvestigationAgent(case_dir).list_runs()


def show_investigation_run(case_id: str, run_id: str):
    manager = CaseManager()
    manager.load_case(case_id)
    case_dir = manager.root / case_id
    return AutonomousInvestigationAgent(case_dir).load_run(run_id)
