from __future__ import annotations

from app.forensics.case_manager import CaseManager
from app.forensics.correlation import CorrelationEngine
from app.forensics.evidence import EvidenceManager
from app.forensics.event_import import import_jsonl_events, timeline_summary
from app.forensics.investigation import InvestigationEngine
from app.forensics.macos_logs import MacOSLogAdapter
from app.forensics.volatility import VolatilityAdapter


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


def correlate_case(case_id: str, window_seconds: int = 300):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return CorrelationEngine(case_dir).analyze(window_seconds=window_seconds)


def investigate_case(case_id: str, window_seconds: int = 120, max_findings: int = 25):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return InvestigationEngine(case_dir).analyze(
        window_seconds=window_seconds,
        max_findings=max_findings,
    )


def collect_macos_logs(
    case_id: str,
    last: str = "5m",
    predicate: str | None = None,
    max_events: int = 1000,
):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return MacOSLogAdapter(case_dir).collect(
        last=last,
        predicate=predicate,
        max_events=max_events,
    )


def volatility_status():
    return VolatilityAdapter.status()


def run_volatility(
    case_id: str,
    image_path: str,
    plugin: str,
    evidence_id: str | None = None,
):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return VolatilityAdapter(case_dir).run(
        image_path=image_path,
        plugin=plugin,
        evidence_id=evidence_id,
    )
