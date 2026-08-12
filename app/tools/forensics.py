from __future__ import annotations

from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager


def create_case(title: str, description: str = ""):
    return CaseManager().create_case(title=title, description=description)


def register_evidence(case_id: str, path: str):
    return EvidenceManager().register(case_id=case_id, source_path=path, copy=True)


def verify_evidence(case_id: str, evidence_id: str | None = None):
    return EvidenceManager().verify(case_id=case_id, evidence_id=evidence_id)


def show_case(case_id: str):
    return CaseManager().load_case(case_id)
