from app.brain.planner import plan_command
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_network_intelligence_aggregates_flows(tmp_path):
    case_dir = tmp_path / "DFIR-NET"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T19:00:00+00:00",
        source="tshark",
        event_type="network",
        summary="10.0.0.5 → 8.8.8.8 DNS=example.com",
        details={
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "udp_srcport": "53000",
            "udp_dstport": "53",
            "dns_query": "example.com",
            "protocols": "eth:ip:udp:dns",
        },
        evidence_id="E0003",
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T19:00:01+00:00",
        source="tshark",
        event_type="network",
        summary="10.0.0.5 → 8.8.8.8 DNS=example.com",
        details={
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "udp_srcport": "53000",
            "udp_dstport": "53",
            "dns_query": "example.com",
            "protocols": "eth:ip:udp:dns",
        },
        evidence_id="E0003",
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T19:00:02+00:00",
        source="tshark",
        event_type="network",
        summary="10.0.0.5 → 1.1.1.1",
        details={
            "src": "10.0.0.5",
            "dst": "1.1.1.1",
            "udp_srcport": "54000",
            "udp_dstport": "4444",
            "protocols": "eth:ip:udp:data",
        },
        evidence_id="E0003",
    ))

    result = NetworkIntelligenceEngine(case_dir).analyze()
    assert result["network_event_count"] == 3
    assert result["flow_count"] == 2
    assert result["dns_queries"] == {"example.com": 2}
    assert result["flows"][0]["packet_count"] == 2
    assert len(result["findings"]["unusual_destination_ports"]) == 1


def test_network_intelligence_planner_command():
    plan = plan_command("network intelligence DFIR-2026-0001 25")
    assert plan.steps[0].tool == "forensic.network_intelligence"
    assert plan.steps[0].arguments == {"case_id": "DFIR-2026-0001", "max_flows": 25}
