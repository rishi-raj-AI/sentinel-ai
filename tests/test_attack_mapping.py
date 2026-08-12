from app.brain.planner import plan_command
from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_attack_mapping_detects_powershell_candidate(tmp_path):
    case_dir = tmp_path / "DFIR-ATTACK"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:00+00:00",
        source="volatility:windows.cmdline",
        event_type="process",
        summary="powershell.exe -EncodedCommand AAAA",
        details={"Process": "powershell.exe", "CommandLine": "powershell.exe -EncodedCommand AAAA"},
        evidence_id="E0004",
    ))

    result = AttackMappingEngine(case_dir).analyze()
    ids = {candidate["technique_id"] for candidate in result["candidates"]}
    assert "T1059.001" in ids


def test_attack_mapping_does_not_map_plain_dns_without_suspicious_context(tmp_path):
    case_dir = tmp_path / "DFIR-DNS"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:00+00:00",
        source="tshark",
        event_type="network",
        summary="10.0.0.5 -> 8.8.8.8 DNS=example.com",
        details={
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "udp_srcport": "53000",
            "udp_dstport": "53",
            "dns_query": "example.com",
        },
        evidence_id="E0003",
    ))

    result = AttackMappingEngine(case_dir).analyze()
    ids = {candidate["technique_id"] for candidate in result["candidates"]}
    assert "T1071.004" not in ids


def test_attack_mapping_planner_command():
    plan = plan_command("attack mapping DFIR-2026-0001 20")
    assert plan.steps[0].tool == "forensic.attack_mapping"
    assert plan.steps[0].arguments == {"case_id": "DFIR-2026-0001", "max_candidates": 20}
