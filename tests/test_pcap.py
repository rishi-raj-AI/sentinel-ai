from app.brain.planner import plan_command
from app.forensics.pcap import TsharkAdapter


def test_tshark_status_shape():
    status = TsharkAdapter.status()
    assert "available" in status
    assert "executable" in status


def test_pcap_planner_command():
    plan = plan_command("pcap evidence DFIR-2026-0001 E0003 250")
    assert plan.steps[0].tool == "forensic.analyze_pcap_evidence"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "evidence_id": "E0003",
        "max_packets": 250,
    }


def test_tshark_status_planner_command():
    plan = plan_command("tshark status")
    assert plan.steps[0].tool == "forensic.tshark_status"
