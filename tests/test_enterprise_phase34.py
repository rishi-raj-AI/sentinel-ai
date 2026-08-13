from pathlib import Path

from fastapi.testclient import TestClient

from app.enterprise.core import InvestigationReasoningService, KnowledgeGraphService
from app.enterprise.workspace import JobStore, PluginRegistry, PluginSpec, RBAC, WorkspaceStore
from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.web import create_dashboard_app


def _case(tmp_path):
    cases_root = tmp_path / "cases"
    manager = CaseManager(str(cases_root))
    case = manager.create_case("Phase 3/4 enterprise test")
    case_id = case["case_id"]
    case_dir = cases_root / case_id
    evidence = tmp_path / "capture.pcap"
    evidence.write_bytes(b"enterprise-test")
    EvidenceManager(str(cases_root)).register(case_id, str(evidence))
    TimelineStore(case_dir).append(TimelineEvent(
        timestamp="2026-08-13T01:00:00+00:00", source="tshark", event_type="network",
        summary="192.0.2.10 -> 198.51.100.20",
        details={"src":"192.0.2.10", "dst":"198.51.100.20", "udp_srcport":"54000", "udp_dstport":"4444", "protocols":"eth:ip:udp:data"},
        evidence_id="E0001",
    ))
    return cases_root, case_dir, case_id


def test_knowledge_graph_snapshot_neighbors_and_path(tmp_path):
    _, case_dir, _ = _case(tmp_path)
    service = KnowledgeGraphService(case_dir)
    graph = service.snapshot()
    assert graph["version"] == "3.0"
    assert graph["node_count"] > 0 and graph["edge_count"] > 0
    assert "ip" in graph["node_types"]
    source = "ip:192.0.2.10"
    target = "ip:198.51.100.20"
    assert service.neighbors(source)["found"] is True
    result = service.shortest_path(source, target)
    assert result["found"] is True
    assert result["path"][0] == source and result["path"][-1] == target


def test_cross_case_correlation(tmp_path):
    root, case_dir, case_id = _case(tmp_path)
    result = KnowledgeGraphService.cross_case_correlate([case_dir], "198.51.100.20")
    assert result["case_count"] == 1
    assert result["matches"][0]["case_id"] == case_id


def test_explainable_hypothesis_score_penalizes_contradictions_and_gaps(tmp_path):
    _, case_dir, _ = _case(tmp_path)
    service = InvestigationReasoningService(case_dir)
    strong = service.score_hypothesis("possible beaconing", supporting=["FLOW:1", "SIGMA:1"], source_quality=0.9)
    weak = service.score_hypothesis("possible beaconing", supporting=["FLOW:1"], contradicting=["known updater"], gaps=["no memory"], source_quality=0.5)
    assert strong.confidence > weak.confidence
    assert weak.components["contradiction_penalty"] > 0
    assert weak.components["gap_penalty"] > 0


def test_workspace_rbac_and_activity(tmp_path):
    _, case_dir, _ = _case(tmp_path)
    store = WorkspaceStore(case_dir)
    note = store.add("note", actor="alice", role="analyst", text="Review UDP 4444")
    assert note["id"].startswith("NOTE-")
    try:
        store.add("assignment", actor="alice", role="analyst", assignee="bob")
        assert False, "analyst must not assign cases"
    except PermissionError:
        pass
    assignment = store.add("assignment", actor="lead", role="lead", assignee="bob")
    assert assignment["id"].startswith("ASSIGNMENT-")
    snapshot = store.snapshot(role="viewer")
    assert len(snapshot["activity"]) == 2
    assert RBAC.allowed("viewer", "workspace.write") is False


def test_plugin_registry_and_job_store(tmp_path):
    registry = PluginRegistry()
    registry.register(PluginSpec("echo", "1", "test plugin"), lambda value: {"value": value})
    assert registry.invoke("echo", value="ok") == {"value": "ok"}
    jobs = JobStore(tmp_path / "jobs.db")
    job_id = jobs.submit("echo", {"value":"ok"})
    result = jobs.run(job_id, lambda value: {"value": value})
    assert result["state"] == "completed"


def test_enterprise_api_routes_and_roles(tmp_path):
    cases_root, _, case_id = _case(tmp_path)
    client = TestClient(create_dashboard_app(cases_root=str(cases_root)))
    graph = client.get(f"/api/enterprise/cases/{case_id}/graph")
    assert graph.status_code == 200
    denied = client.post(
        f"/api/enterprise/cases/{case_id}/workspace",
        headers={"x-sentinel-role":"viewer"},
        json={"kind":"note", "actor":"viewer", "fields":{"text":"nope"}},
    )
    assert denied.status_code == 403
    created = client.post(
        f"/api/enterprise/cases/{case_id}/workspace",
        headers={"x-sentinel-role":"analyst"},
        json={"kind":"note", "actor":"alice", "fields":{"text":"review flow"}},
    )
    assert created.status_code == 200
    replay = client.get(f"/api/enterprise/cases/{case_id}/replay")
    assert replay.status_code == 200
    assert replay.json()["events"]
