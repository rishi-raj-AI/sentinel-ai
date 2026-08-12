from app.brain.planner import plan_command
from app.forensics.attack_chain import AttackChainEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_attack_chain_orders_timestamped_candidate(tmp_path):
    case_dir = tmp_path / "DFIR-CHAIN"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:00+00:00",
        source="volatility:windows.cmdline",
        event_type="process",
        summary="powershell.exe -EncodedCommand AAAA",
        details={"Process": "powershell.exe", "CommandLine": "powershell.exe -EncodedCommand AAAA"},
        evidence_id="E0004",
    ))

    result = AttackChainEngine(case_dir).build()
    assert result["stage_count"] >= 1
    assert result["stages"][0]["technique_id"] == "T1059.001"
    assert result["stages"][0]["chronology_status"] == "observed_timestamp"
    assert result["summary"]["is_proven_attack_chain"] is False


def test_attack_chain_planner_command():
    plan = plan_command("attack chain DFIR-2026-0001 20")
    assert plan.steps[0].tool == "forensic.attack_chain"
    assert plan.steps[0].arguments == {"case_id": "DFIR-2026-0001", "max_candidates": 20}
