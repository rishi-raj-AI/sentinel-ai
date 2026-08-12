from pathlib import Path

import pytest

from app.audit.logger import AuditLogger
from app.brain.planner import plan_command
from app.executor import ConfirmationRequired, Executor
from app.forensics.case_manager import CaseManager
from app.forensics.chain_of_custody import ChainOfCustody
from app.forensics.evidence import EvidenceManager
from app.forensics.event_import import import_jsonl_events, timeline_summary
from app.memory.store import MemoryStore


def test_planner_creates_registered_list_action() -> None:
    plan = plan_command("list .")
    assert plan.requires_action is True
    assert plan.steps[0].tool == "filesystem.list_directory"


def test_unknown_command_does_not_execute() -> None:
    plan = plan_command("launch hyperspace")
    assert plan.requires_action is False
    assert plan.steps == []


def test_sha256_execution(tmp_path: Path) -> None:
    evidence = tmp_path / "sample.txt"
    evidence.write_text("sentinel", encoding="utf-8")
    plan = plan_command(f"sha256 {evidence}")
    executor = Executor(AuditLogger(str(tmp_path / "audit.db")))
    result = executor.execute(plan)
    assert result[0].success is True
    assert len(result[0].output) == 64


def test_modification_requires_confirmation(tmp_path: Path) -> None:
    plan = plan_command(f"mkdir {tmp_path / 'created'}")
    executor = Executor(AuditLogger(str(tmp_path / "audit.db")))
    with pytest.raises(ConfirmationRequired):
        executor.execute(plan)
    result = executor.execute(plan, confirmed=True)
    assert result[0].success is True
    assert (tmp_path / "created").is_dir()


def test_memory_persists_between_instances(tmp_path: Path) -> None:
    db = str(tmp_path / "memory.db")
    first = MemoryStore(db)
    first.set("owner_name", "Rishi")
    second = MemoryStore(db)
    assert second.get("owner_name") == "Rishi"


def test_forensic_case_and_evidence_verification(tmp_path: Path) -> None:
    cases_root = tmp_path / "cases"
    case = CaseManager(str(cases_root)).create_case("Unit test investigation")
    source = tmp_path / "artifact.txt"
    source.write_text("forensic evidence", encoding="utf-8")

    manager = EvidenceManager(str(cases_root))
    evidence = manager.register(case["case_id"], str(source))
    verification = manager.verify(case["case_id"], evidence["evidence_id"])

    assert verification["all_match"] is True
    assert verification["chain_of_custody_valid"] is True
    assert len(evidence["sha256"]) == 64


def test_chain_of_custody_detects_tampering(tmp_path: Path) -> None:
    case = CaseManager(str(tmp_path / "cases")).create_case("Tamper test")
    case_dir = tmp_path / "cases" / case["case_id"]
    ledger = ChainOfCustody(case_dir)
    ledger.append("test_event", {"value": 1})
    assert ledger.verify() is True

    content = ledger.path.read_text(encoding="utf-8").replace('"value": 1', '"value": 2')
    ledger.path.write_text(content, encoding="utf-8")
    assert ledger.verify() is False


def test_jsonl_events_normalize_into_timeline(tmp_path: Path) -> None:
    case_dir = tmp_path / "DFIR-TEST"
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"timestamp":"2026-08-12T18:00:00Z","event_type":"login","message":"User login"}\n'
        '{"timestamp":"2026-08-12T18:05:00+00:00","event_type":"process","summary":"Process started"}\n',
        encoding="utf-8",
    )

    result = import_jsonl_events(case_dir, str(source), source_name="testlog", evidence_id="E0001")
    summary = timeline_summary(case_dir)

    assert result["events_ingested"] == 2
    assert summary["event_count"] == 2
    assert summary["by_source"] == {"testlog": 2}
    assert summary["by_type"] == {"login": 1, "process": 1}
    assert summary["events"][0]["evidence_id"] == "E0001"


def test_timeline_planner_commands() -> None:
    import_plan = plan_command("import events DFIR-2026-0001 workspace/events.jsonl macos")
    assert import_plan.steps[0].tool == "forensic.import_events"
    assert import_plan.steps[0].arguments["source_name"] == "macos"

    timeline_plan = plan_command("timeline DFIR-2026-0001")
    assert timeline_plan.steps[0].tool == "forensic.show_timeline"
