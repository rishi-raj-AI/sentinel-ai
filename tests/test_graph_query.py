from app.brain.planner import plan_command
from app.forensics.graph_query import EvidenceGraphQueryEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def _case(tmp_path):
    case_dir = tmp_path / "DFIR-GRAPH-QUERY"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:00+00:00",
        source="tshark",
        event_type="network",
        summary="10.0.0.5 → 8.8.8.8",
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
    return case_dir


def test_graph_neighbors_resolves_ip(tmp_path):
    result = EvidenceGraphQueryEngine(_case(tmp_path)).neighbors("ip:10.0.0.5", depth=1)
    assert result["resolved"] is True
    ids = {node["id"] for node in result["nodes"]}
    assert "ip:8.8.8.8" in ids


def test_graph_trace_finds_evidence_to_destination_path(tmp_path):
    result = EvidenceGraphQueryEngine(_case(tmp_path)).trace("evidence:E0003", "ip:8.8.8.8", max_hops=4)
    assert result["resolved"] is True
    assert result["path_found"] is True
    assert result["hop_count"] <= 4


def test_graph_neighbor_planner_command():
    plan = plan_command("graph neighbors DFIR-2026-0001 ip:192.0.2.10 2 50")
    assert plan.steps[0].tool == "forensic.graph_neighbors"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "query": "ip:192.0.2.10",
        "depth": 2,
        "max_results": 50,
    }


def test_graph_trace_planner_command():
    plan = plan_command("graph trace DFIR-2026-0001 evidence:E0003 ip:198.51.100.20 5")
    assert plan.steps[0].tool == "forensic.graph_trace"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "source": "evidence:E0003",
        "target": "ip:198.51.100.20",
        "max_hops": 5,
    }
