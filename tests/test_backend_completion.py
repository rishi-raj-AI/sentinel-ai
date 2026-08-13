from fastapi.testclient import TestClient

from app.cyberbrain.backend_snapshot import BackendSnapshotService
from app.web import create_dashboard_app


def test_x1112_routes_status_evaluation_and_insights(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DATA_ROOT", str(tmp_path / "data"))
    app = create_dashboard_app(cases_root=str(tmp_path / "cases"))
    client = TestClient(app)

    status = client.get("/api/x/status")
    assert status.status_code == 200
    assert status.json()["generation"] == "X12"

    denied = client.post("/api/x/evaluation/scenarios", json={
        "scenario_id": "EVAL-1", "name": "Quality", "domain": "dfir",
        "description": "quality scenario", "expected": {"grounded": True},
    })
    assert denied.status_code == 403

    headers = {"X-Sentinel-Role": "lead"}
    created = client.post("/api/x/evaluation/scenarios", headers=headers, json={
        "scenario_id": "EVAL-1", "name": "Quality", "domain": "dfir",
        "description": "quality scenario", "expected": {"grounded": True},
    })
    assert created.status_code == 200

    result = client.post("/api/x/evaluation/results", headers=headers, json={
        "scenario_id": "EVAL-1", "system": "sentinel-x", "passed": True,
        "score": 0.9, "grounded_rate": 1.0, "false_positive_rate": 0.0,
    })
    assert result.status_code == 200
    board = client.get("/api/x/evaluation/leaderboard")
    assert board.status_code == 200
    assert board.json()["leaderboard"][0]["system"] == "sentinel-x"

    insight = client.post("/api/x/insights", headers=headers, json={
        "category": "coverage-gap", "summary": "Generalized coverage gap",
        "confidence": 0.8, "frequency": 3, "source_count": 2,
        "attributes": {"platform": "endpoint"},
    })
    assert insight.status_code == 200

    rejected = client.post("/api/x/insights", headers=headers, json={
        "category": "bad", "summary": "reject", "confidence": 0.8,
        "frequency": 2, "source_count": 2, "attributes": {"tenant_id": "ORG-1"},
    })
    assert rejected.status_code == 400


def test_backend_snapshot_manifest(tmp_path):
    service = BackendSnapshotService(tmp_path / "data")
    manifest = service.manifest()
    assert manifest["version"] == "backend-snapshot-v1"
    assert manifest["platform"]["generation"] == "X12"
    path = service.write_manifest()
    assert path.is_file()
