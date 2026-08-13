from fastapi.testclient import TestClient

from app.enterprise.workspace import replay_events
from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.soc.core_v2 import SOCSupervisor
from app.web import create_dashboard_app


class DummyCopilot:
    def __init__(self, *args, **kwargs):
        pass

    def answer(self, question, max_sources=16):
        return {
            "mode": "model",
            "model": "test-model",
            "answer": "Grounded supervisor synthesis for test case.",
            "provider_error": None,
            "source_count": 2,
        }


def _case(tmp_path):
    root = tmp_path / "cases"
    manager = CaseManager(str(root))
    case = manager.create_case("Phase 5 SOC test")
    case_id = case["case_id"]
    case_dir = root / case_id
    evidence = tmp_path / "capture.pcap"
    evidence.write_bytes(b"soc-test")
    EvidenceManager(str(root)).register(case_id, str(evidence))
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-13T09:00:00+00:00", source="tshark", event_type="network",
        summary="192.0.2.10 -> 198.51.100.20",
        details={"src":"192.0.2.10", "dst":"198.51.100.20", "udp_srcport":"54000", "udp_dstport":"4444", "protocols":"eth:ip:udp:data"},
        evidence_id="E0001",
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-13T09:01:00+00:00", source="yara", event_type="yara_match",
        summary="Sentinel_Test_Artifact matched",
        details={"rule":"Sentinel_Test_Artifact"}, evidence_id="E0001",
    ))
    return root, case_dir, case_id


def test_soc_supervisor_runs_all_specialists_and_persists(monkeypatch, tmp_path):
    root, case_dir, case_id = _case(tmp_path)
    monkeypatch.setattr("app.soc.core_v2.CaseCopilot", DummyCopilot)
    result = SOCSupervisor(case_dir).run("Investigate possible malicious activity", role="analyst")
    assert result["version"] == "5.1"
    assert result["case_id"] == case_id
    assert result["agent_count"] == 5
    assert {row["agent"] for row in result["agents"]} == {
        "network-analyst", "detection-analyst", "memory-analyst", "threat-hunter", "counter-evidence-agent"
    }
    assert len(result["transcript"]) == 6
    assert result["guardrails"]["read_only"] is True
    assert result["guardrails"]["endpoint_remediation"] is False
    assert 0 <= result["supervisor_hypothesis"]["confidence"] <= 1
    assert result["artifacts"]["json"]["sha256"]
    assert result["artifacts"]["markdown"]["sha256"]
    assert SOCSupervisor(case_dir).list_runs()[0]["run_id"] == result["run_id"]
    assert SOCSupervisor(case_dir).load_run(result["run_id"])["objective"] == result["objective"]
    replay = replay_events(case_dir)
    assert any(row.get("action") == "soc.run" and row.get("item_id") == result["run_id"] for row in replay)


def test_soc_preserves_counter_evidence_and_collection_gaps(monkeypatch, tmp_path):
    _, case_dir, _ = _case(tmp_path)
    monkeypatch.setattr("app.soc.core_v2.CaseCopilot", DummyCopilot)
    result = SOCSupervisor(case_dir).run("Assess compromise", role="analyst", persist=False)
    detection = next(row for row in result["agents"] if row["agent"] == "detection-analyst")
    memory = next(row for row in result["agents"] if row["agent"] == "memory-analyst")
    counter = next(row for row in result["agents"] if row["agent"] == "counter-evidence-agent")
    assert detection["contradicting"]
    assert "test-like" in detection["contradicting"][0].lower()
    assert memory["gaps"]
    assert result["collection_gaps"]
    assert result["supervisor_hypothesis"]["components"]["gap_penalty"] > 0
    assert counter["metrics"]["confidence_method"]["method"] == "weighted_top_relevance"


def test_soc_requires_analyst_role(tmp_path):
    _, case_dir, _ = _case(tmp_path)
    try:
        SOCSupervisor(case_dir).run("Investigate", role="viewer", persist=False)
        assert False, "viewer must not launch SOC analysis"
    except PermissionError:
        pass


def test_soc_api_roles_history_and_run(monkeypatch, tmp_path):
    root, _, case_id = _case(tmp_path)
    monkeypatch.setattr("app.soc.core_v2.CaseCopilot", DummyCopilot)
    client = TestClient(create_dashboard_app(cases_root=str(root)))
    agents = client.get("/api/soc/agents")
    assert agents.status_code == 200
    assert agents.json()["version"] == "5.1"
    assert len(agents.json()["agents"]) == 6
    denied = client.post(
        f"/api/soc/cases/{case_id}/runs",
        headers={"x-sentinel-role":"viewer"},
        json={"objective":"Investigate possible malicious activity"},
    )
    assert denied.status_code == 403
    created = client.post(
        f"/api/soc/cases/{case_id}/runs",
        headers={"x-sentinel-role":"analyst"},
        json={"objective":"Investigate possible malicious activity"},
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]
    history = client.get(f"/api/soc/cases/{case_id}/runs")
    assert history.status_code == 200 and history.json()[0]["run_id"] == run_id
    loaded = client.get(f"/api/soc/cases/{case_id}/runs/{run_id}")
    assert loaded.status_code == 200
    assert loaded.json()["agent_count"] == 5
