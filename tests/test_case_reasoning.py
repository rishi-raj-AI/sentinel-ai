from pathlib import Path

from app.brain.planner_ext import plan_command
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.threat_intel import ThreatIntelEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_case_brief_correlates_sigma_and_network(tmp_path):
    case_dir = tmp_path / "case"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T19:30:08+00:00",
        source="tshark",
        event_type="network",
        summary="192.0.2.10 → 198.51.100.20",
        details={
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "udp_srcport": "54000",
            "udp_dstport": "4444",
            "protocols": "eth:ip:udp:data",
        },
        evidence_id="E0003",
    ))

    result = CaseReasoningEngine(case_dir).build(max_items=10)
    assert result["coverage"]["sigma_detections"] >= 1
    assert result["coverage"]["pcap_events"] == 1
    assert any(item["kind"] == "sigma_detection" for item in result["observations"])
    assert result["recommended_actions"]
    assert "verdict" in result["interpretation"].lower()


def test_threat_intel_inventory_is_local_and_classifies_documentation(tmp_path):
    case_dir = tmp_path / "case"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T19:30:08+00:00",
        source="tshark",
        event_type="network",
        summary="flow",
        details={"src": "192.0.2.10", "dst": "198.51.100.20", "dns_query": "example.test"},
        evidence_id="E0003",
    ))
    result = ThreatIntelEngine(case_dir).inventory()
    assert result["summary"]["external_lookup_performed"] is False
    assert all(row["scope"] == "documentation" for row in result["ips"])


def test_planner_routes_case_brief_and_threat_intel():
    brief = plan_command("case brief DFIR-2026-0001 20")
    assert brief.steps[0].tool == "forensic.case_brief"
    intel = plan_command("threat intel DFIR-2026-0001 100")
    assert intel.steps[0].tool == "forensic.threat_intel_inventory"
