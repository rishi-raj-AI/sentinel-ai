from pathlib import Path

import pytest

from app.audit.logger import AuditLogger
from app.brain.planner import plan_command
from app.executor import ConfirmationRequired, Executor
from app.forensics.case_manager import CaseManager
from app.forensics.chain_of_custody import ChainOfCustody
from app.forensics.correlation import CorrelationEngine
from app.forensics.evidence import EvidenceManager
from app.forensics.event_import import import_jsonl_events, timeline_summary
from app.forensics.macos_logs import MacOSLogAdapter
from app.forensics.timeline import TimelineEvent, TimelineStore
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


def test_correlation_finds_relationships_and_network_anomaly(tmp_path: Path) -> None:
    case_dir = tmp_path / "DFIR-TEST"
    source = tmp_path / "events.jsonl"
    source.write_text(
        '{"timestamp":"2026-08-12T18:00:00Z","event_type":"login","message":"User login"}\n'
        '{"timestamp":"2026-08-12T18:01:00Z","event_type":"process","message":"Process started"}\n'
        '{"timestamp":"2026-08-12T18:02:00Z","event_type":"network","message":"Outbound connection"}\n',
        encoding="utf-8",
    )
    import_jsonl_events(case_dir, str(source), source_name="testlog")
    result = CorrelationEngine(case_dir).analyze(window_seconds=180)
    assert result["event_count"] == 3
    assert result["summary"]["relationship_count"] >= 2
    assert result["summary"]["anomaly_count"] == 1
    assert result["anomalies"][0]["reason"] == "Outbound or remote network activity"


def test_correlation_deduplicates_noisy_events(tmp_path: Path) -> None:
    store = TimelineStore(tmp_path / "DFIR-NOISE")
    for index in range(100):
        store.append(TimelineEvent(
            timestamp=f"2026-08-12T18:42:36.{index:06d}+00:00",
            source="macos_unified_log",
            event_type="info",
            summary="WindowServer: repeated status message",
            details={},
        ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:42:38+00:00",
        source="macos_unified_log",
        event_type="network",
        summary="Outbound connection",
        details={},
    ))

    result = CorrelationEngine(tmp_path / "DFIR-NOISE").analyze(window_seconds=60)
    assert result["raw_event_count"] == 101
    assert result["duplicates_removed"] >= 99
    assert result["event_count"] <= 2
    assert result["summary"]["anomaly_count"] == 1


def test_correlation_caps_large_timelines(tmp_path: Path) -> None:
    store = TimelineStore(tmp_path / "DFIR-LARGE")
    for index in range(40):
        store.append(TimelineEvent(
            timestamp=f"2026-08-12T18:{index // 60:02d}:{index % 60:02d}+00:00",
            source="test",
            event_type="process" if index % 2 else "login",
            summary=f"event-{index}",
            details={},
        ))
    result = CorrelationEngine(tmp_path / "DFIR-LARGE").analyze(
        window_seconds=60,
        max_events=10,
        max_relationships=5,
        sequence_limit=4,
        dedup_seconds=0,
    )
    assert result["event_count"] == 10
    assert result["analysis_truncated"] is True
    assert len(result["sequence"]) == 4
    assert len(result["relationships"]) <= 5


def test_correlation_planner_command() -> None:
    plan = plan_command("correlate DFIR-2026-0001 180")
    assert plan.steps[0].tool == "forensic.correlate_case"
    assert plan.steps[0].arguments["window_seconds"] == 180


def test_macos_log_record_normalizes() -> None:
    event = MacOSLogAdapter._normalize({
        "timestamp": "2026-08-12T18:30:00.000000+01:00",
        "process": "loginwindow",
        "processID": 123,
        "messageType": "Default",
        "eventMessage": "Session event",
        "subsystem": "com.apple.loginwindow",
        "category": "session",
    })
    assert event is not None
    assert event.source == "macos_unified_log"
    assert event.event_type == "default"
    assert event.timestamp.endswith("+00:00")
    assert "loginwindow" in event.summary


def test_macos_log_planner_command() -> None:
    plan = plan_command("collect macos logs DFIR-2026-0001 2m")
    assert plan.steps[0].tool == "forensic.collect_macos_logs"
    assert plan.steps[0].arguments == {"case_id": "DFIR-2026-0001", "last": "2m"}
