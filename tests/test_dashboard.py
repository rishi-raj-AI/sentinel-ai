from pathlib import Path

from fastapi.testclient import TestClient

from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.web.dashboard import create_dashboard_app


def _build_dashboard_case(tmp_path):
    cases_root = tmp_path / "cases"
    manager = CaseManager(str(cases_root))
    case = manager.create_case("Dashboard integration test")
    case_id = case["case_id"]
    case_dir = cases_root / case_id

    evidence = tmp_path / "sample.txt"
    evidence.write_text("dashboard evidence", encoding="utf-8")
    EvidenceManager(str(cases_root)).register(case_id, str(evidence))

    TimelineStore(case_dir).append(TimelineEvent(
        timestamp="2026-08-12T19:30:08+00:00",
        source="tshark",
        event_type="network",
        summary="192.0.2.10 -> 198.51.100.20",
        details={
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "udp_srcport": "54000",
            "udp_dstport": "4444",
            "protocols": "eth:ip:udp:data",
        },
        evidence_id="E0001",
    ))

    reports = case_dir / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "sample-report.html").write_text("<html>report</html>", encoding="utf-8")
    return cases_root, case_id


def test_dashboard_endpoints_and_ui(tmp_path):
    cases_root, case_id = _build_dashboard_case(tmp_path)
    app = create_dashboard_app(cases_root=str(cases_root), sigma_rules="rules/sigma")
    client = TestClient(app)

    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["mode"] == "local-read-only-dashboard"

    index = client.get("/")
    assert index.status_code == 200
    assert "SENTINEL" in index.text
    assert "Investigator Assistant" in index.text

    cases = client.get("/api/cases")
    assert cases.status_code == 200
    assert cases.json()[0]["case_id"] == case_id

    overview = client.get(f"/api/cases/{case_id}/overview")
    assert overview.status_code == 200
    payload = overview.json()
    assert payload["stats"]["events"] == 1
    assert payload["stats"]["evidence"] == 1
    assert payload["stats"]["sigma_detections"] >= 1
    assert payload["brief"]["headline"]

    timeline = client.get(f"/api/cases/{case_id}/timeline?limit=10")
    assert timeline.status_code == 200
    assert timeline.json()["returned"] == 1
    assert timeline.json()["events"][0]["event_type"] == "network"

    detections = client.get(f"/api/cases/{case_id}/detections")
    assert detections.status_code == 200
    assert detections.json()["sigma"]["detection_count"] >= 1

    graph = client.get(f"/api/cases/{case_id}/graph?max_nodes=50&max_edges=100")
    assert graph.status_code == 200
    assert graph.json()["node_count"] > 0
    assert graph.json()["edge_count"] > 0

    reports = client.get(f"/api/cases/{case_id}/reports")
    assert reports.status_code == 200
    assert any(item["name"] == "sample-report.html" for item in reports.json())

    report = client.get(f"/api/cases/{case_id}/reports/sample-report.html")
    assert report.status_code == 200
    assert "report" in report.text

    chat = client.post(f"/api/cases/{case_id}/chat", json={"question": "What network activity should I review?"})
    assert chat.status_code == 200
    assert "4444" in chat.json()["answer"]
    assert "network_intelligence" in chat.json()["sources"]


def test_dashboard_rejects_unknown_case_and_report_traversal(tmp_path):
    cases_root, case_id = _build_dashboard_case(tmp_path)
    app = create_dashboard_app(cases_root=str(cases_root), sigma_rules="rules/sigma")
    client = TestClient(app)

    missing = client.get("/api/cases/DFIR-2099-9999/overview")
    assert missing.status_code == 404

    traversal = client.get(f"/api/cases/{case_id}/reports/..%2Fcase.json")
    assert traversal.status_code == 404
