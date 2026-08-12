from app.brain.planner import plan_command
from app.forensics.pcap import TsharkAdapter
from app.forensics.sample_pcap import create_sample_pcap


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


def test_sample_pcap_generator(tmp_path):
    target = tmp_path / "sample.pcap"
    result = create_sample_pcap(str(target))
    assert target.is_file()
    assert result["packets_written"] == 2
    assert result["size_bytes"] > 24
    # Classic little-endian PCAP magic bytes.
    assert target.read_bytes()[:4] == bytes.fromhex("d4c3b2a1")


def test_sample_pcap_planner_command():
    plan = plan_command("create sample pcap workspace/sample.pcap")
    assert plan.steps[0].tool == "forensic.create_sample_pcap"
    assert plan.steps[0].arguments == {"path": "workspace/sample.pcap"}
