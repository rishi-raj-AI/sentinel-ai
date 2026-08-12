from app.brain.planner import plan_command
from app.forensics.investigation import InvestigationEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_investigation_filters_low_value_noise(tmp_path):
    case_dir = tmp_path / "DFIR-INV"
    store = TimelineStore(case_dir)
    for index in range(50):
        store.append(TimelineEvent(
            timestamp=f"2026-08-12T18:00:{index:02d}+00:00",
            source="macos_unified_log",
            event_type="info",
            summary="WindowServer routine status",
            details={},
        ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:01:00+00:00",
        source="test",
        event_type="network",
        summary="Outbound remote connection",
        details={},
    ))

    result = InvestigationEngine(case_dir).analyze()
    assert result["raw_event_count"] == 51
    assert result["noise_removed"] >= 50
    assert result["relevant_event_count"] == 1
    assert result["summary"]["finding_count"] >= 1


def test_investigation_builds_high_confidence_chain(tmp_path):
    case_dir = tmp_path / "DFIR-CHAIN"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:00:00+00:00",
        source="test",
        event_type="login",
        summary="User login",
        details={},
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:00:20+00:00",
        source="test",
        event_type="process",
        summary="osascript process started",
        details={},
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:00:40+00:00",
        source="test",
        event_type="network",
        summary="Outbound remote connection",
        details={},
    ))

    result = InvestigationEngine(case_dir).analyze(window_seconds=60)
    chains = [item for item in result["findings"] if "→" in item["title"]]
    assert chains
    assert chains[0]["confidence"] == "high"
    assert chains[0]["severity"] == "high"


def test_investigation_planner_command():
    plan = plan_command("investigate DFIR-2026-0001 120 10")
    assert plan.steps[0].tool == "forensic.investigate_case"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "window_seconds": 120,
        "max_findings": 10,
    }
