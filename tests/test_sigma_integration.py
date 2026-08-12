from app.forensics.case_manager import CaseManager
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.tools.forensics import investigate_case


def _add_udp_4444_event(case_dir):
    TimelineStore(case_dir).append(TimelineEvent(
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


def test_investigation_includes_sigma_findings(tmp_path, monkeypatch):
    cases_root = tmp_path / "cases"
    manager = CaseManager(str(cases_root))
    case = manager.create_case("Sigma investigation integration")
    case_dir = cases_root / case["case_id"]
    _add_udp_4444_event(case_dir)

    import app.tools.forensics as tools
    monkeypatch.setattr(tools, "CaseManager", lambda: manager)

    result = investigate_case(case["case_id"], max_findings=20)

    assert result["summary"]["sigma_finding_count"] == 1
    assert result["sigma_findings"][0]["rule_id"] == "sentinel-network-udp-4444"
    assert result["sigma_findings"][0]["evidence_id"] == "E0003"
    assert result["sigma_findings"][0]["confidence"] == "high"


def test_evidence_graph_overlays_sigma_detection(tmp_path):
    case_dir = tmp_path / "DFIR-TEST"
    case_dir.mkdir()
    _add_udp_4444_event(case_dir)

    graph = EvidenceGraphEngine(case_dir).build(max_nodes=100, max_edges=200)

    assert graph["summary"]["nodes_by_type"]["sigma_rule"] == 1
    assert graph["summary"]["nodes_by_type"]["detection"] == 1
    relations = graph["summary"]["edges_by_relation"]
    assert relations["triggered_by"] == 1
    assert relations["produced_detection"] == 1
    assert relations["detected"] == 1
    assert any(node["id"] == "sigma_rule:sentinel-network-udp-4444" for node in graph["nodes"])
