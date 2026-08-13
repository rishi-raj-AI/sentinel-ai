from pathlib import Path

from fastapi.testclient import TestClient

from app.brain.planner_ext import plan_command
from app.forensics.autonomous_investigation import AutonomousInvestigationAgent
from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.web import create_dashboard_app


def _case(tmp_path):
    cases_root = tmp_path / "cases"
    manager = CaseManager(str(cases_root))
    case = manager.create_case("Autonomous investigation test")
    case_id = case["case_id"]
    case_dir = cases_root / case_id

    evidence = tmp_path / "capture.pcap"
    evidence.write_bytes(b"sentinel-autonomous-test")
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
    return cases_root, case_dir, case_id


def test_agent_runs_plan_hypotheses_and_persists_notebook(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_MODEL_ENDPOINT", raising=False)
    monkeypatch.delenv("SENTINEL_MODEL_NAME", raising=False)
    monkeypatch.setenv("SENTINEL_MODEL_CONFIG", str(tmp_path / "missing-model.json"))
    _, case_dir, _ = _case(tmp_path)

    result = AutonomousInvestigationAgent(case_dir).run("Investigate possible malware infection", max_items=20)

    assert result["mode"] == "read-only-analysis"
    assert len(result["plan"]) == 7
    assert len(result["notebook"]) == 7
    assert {row["id"] for row in result["hypotheses"]} == {"H1", "H2", "H3"}
    assert 0 <= result["overall_confidence_percent"] <= 100
    assert result["sigma_detections"]
    assert result["network_findings"]["unusual_destination_ports"]

    for artifact in result["artifacts"].values():
        path = Path(artifact["path"])
        assert path.is_file()
        assert len(artifact["sha256"]) == 64
        assert path.stat().st_size == artifact["size_bytes"]

    runs = AutonomousInvestigationAgent(case_dir).list_runs()
    assert runs[0]["run_id"] == result["run_id"]
    loaded = AutonomousInvestigationAgent(case_dir).load_run(result["run_id"])
    assert loaded["objective"] == "Investigate possible malware infection"


def test_autonomous_synthesis_normalizes_valid_model_source_ids(tmp_path, monkeypatch):
    import app.forensics.case_copilot_v3 as copilot_v3

    class FakeProvider:
        configured = True
        model = "test-model"
        configured_model = "test-model"
        persisted_model = "test-model"
        resolved_model = None
        transport = "test"
        active_endpoint = "http://local.test/chat"

        def complete(self, system_prompt: str, user_prompt: str) -> str:
            assert "ALLOWED SOURCE IDS" in user_prompt
            assert "FLOW:1" in user_prompt
            return "The UDP/4444 flow warrants review because it is unusual. Source: FLOW:1"

    monkeypatch.setattr(copilot_v3, "ModelProvider", FakeProvider)
    _, case_dir, _ = _case(tmp_path)

    result = AutonomousInvestigationAgent(case_dir).run(
        "Investigate possible malware infection",
        max_items=20,
        persist=False,
    )

    synthesis = result["synthesis"]
    assert synthesis["mode"] == "model"
    assert synthesis["provider_error"] is None
    assert "[FLOW:1]" in synthesis["answer"]


def test_agent_planner_routes_commands():
    plan = plan_command("autonomous investigate DFIR-2026-0001 Investigate possible malware infection")
    assert plan.steps[0].tool == "forensic.autonomous_investigate"
    assert plan.steps[0].arguments["case_id"] == "DFIR-2026-0001"
    assert "malware" in plan.steps[0].arguments["objective"]

    runs = plan_command("investigation runs DFIR-2026-0001")
    assert runs.steps[0].tool == "forensic.list_investigation_runs"

    show = plan_command("show investigation DFIR-2026-0001 INV-20260813-000000-deadbeef")
    assert show.steps[0].tool == "forensic.show_investigation_run"


def test_autonomous_dashboard_routes(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_MODEL_ENDPOINT", raising=False)
    monkeypatch.delenv("SENTINEL_MODEL_NAME", raising=False)
    monkeypatch.setenv("SENTINEL_MODEL_CONFIG", str(tmp_path / "missing-model.json"))
    cases_root, _, case_id = _case(tmp_path)
    client = TestClient(create_dashboard_app(cases_root=str(cases_root), sigma_rules="rules/sigma"))

    page = client.get("/agent")
    assert page.status_code == 200
    assert "SENTINEL" in page.text and "AGENT" in page.text

    initial = client.get(f"/api/cases/{case_id}/investigations")
    assert initial.status_code == 200
    assert initial.json() == []

    created = client.post(
        f"/api/cases/{case_id}/investigations",
        json={"objective": "Investigate possible malware infection", "max_items": 20},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["run_id"].startswith("INV-")
    assert len(payload["hypotheses"]) == 3

    runs = client.get(f"/api/cases/{case_id}/investigations")
    assert runs.status_code == 200
    assert runs.json()[0]["run_id"] == payload["run_id"]

    loaded = client.get(f"/api/cases/{case_id}/investigations/{payload['run_id']}")
    assert loaded.status_code == 200
    assert loaded.json()["objective"] == "Investigate possible malware infection"
