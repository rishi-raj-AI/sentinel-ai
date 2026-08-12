from __future__ import annotations

from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.event_import import import_jsonl_events, timeline_summary


def create_case(title: str, description: str = ""):
    return CaseManager().create_case(title=title, description=description)


def register_evidence(case_id: str, path: str):
    return EvidenceManager().register(case_id=case_id, source_path=path, copy=True)


def verify_evidence(case_id: str, evidence_id: str | None = None):
    return EvidenceManager().verify(case_id=case_id, evidence_id=evidence_id)


def show_case(case_id: str):
    return CaseManager().load_case(case_id)


def import_events(case_id: str, path: str, source_name: str = "jsonl", evidence_id: str | None = None):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return import_jsonl_events(case_dir, path, source_name=source_name, evidence_id=evidence_id)


def show_timeline(case_id: str):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return timeline_summary(case_dir)
