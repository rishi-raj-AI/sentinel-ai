from app.brain.planner import plan_command
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_evidence_graph_builds_process_ip_domain_relationships(tmp_path):
    case_dir = tmp_path / "DFIR-GRAPH"
    store = TimelineStore(case_dir)

    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:00+00:00",
        source="test",
        event_type="process",
        summary="curl process",
        details={"Name": "curl"},
        evidence_id="E0004",
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:10+00:00",
        source="tshark",
        event_type="network",
        summary="10.0.0.5 → 8.8.8.8 DNS=example.com",
        details={
            "src": "10.0.0.5",
            "dst": "8.8.8.8",
            "udp_srcport": "53000",
            "udp_dstport": "53",
            "dns_query": "example.com",
        },
        evidence_id="E0004",
    ))

    result = EvidenceGraphEngine(case_dir).build()

    assert result["node_count"] >= 6
    assert result["summary"]["nodes_by_type"]["process"] == 1
    assert result["summary"]["nodes_by_type"]["ip"] == 2
    assert result["summary"]["nodes_by_type"]["domain"] == 1
    assert any(edge["relation"] == "connected_to" for edge in result["edges"])
    assert any(edge["relation"] == "queried" for edge in result["edges"])


def test_evidence_graph_planner_command():
    plan = plan_command("evidence graph DFIR-2026-0001 500 1000")
    assert plan.steps[0].tool == "forensic.evidence_graph"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "max_nodes": 500,
        "max_edges": 1000,
    }
