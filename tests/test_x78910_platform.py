from app.cyberbrain.appsec import AppSecAnalyzer
from app.cyberbrain.control_plane import ControlPlaneStore, TenantPolicy
from app.cyberbrain.digital_twin import DigitalTwinStore, TwinEdge, TwinNode
from app.cyberbrain.security_fusion import FusionSignal, SecurityFusionEngine


def test_x7_static_appsec_analysis(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("fastapi==0.1\n", encoding="utf-8")
    (project / "app.py").write_text("TOKEN='1234567890abcdef'\nverify=False\n", encoding="utf-8")
    result = AppSecAnalyzer().analyze(project)
    assert result["version"] == "X7.0"
    assert result["component_count"] == 1
    assert result["finding_count"] >= 2
    assert result["policy"]["read_only"] is True
    assert result["policy"]["static_analysis_only"] is True


def test_x8_digital_twin_simulation_and_coverage(tmp_path):
    store = DigitalTwinStore(tmp_path / "twin.db")
    store.ingest(
        [
            TwinNode("user:a", "identity", "User A", 0.3),
            TwinNode("app:web", "application", "Web App", 0.6),
            TwinNode("db:prod", "database", "Prod DB", 1.0),
        ],
        [
            TwinEdge("user:a", "can-reach", "app:web", 0.8, ["mfa"]),
            TwinEdge("app:web", "can-access", "db:prod", 0.7, []),
        ],
    )
    sim = store.simulate_paths("user:a", target_type="database")
    assert sim["found"] is True
    assert sim["paths"][0]["path"] == ["user:a", "app:web", "db:prod"]
    coverage = store.coverage()
    assert coverage["controlled_edges"] == 1
    assert coverage["uncontrolled_edges"] == 1
    assert coverage["policy"]["simulation_only"] is True


def test_x9_security_fusion_preserves_counter_evidence_and_gaps():
    result = SecurityFusionEngine().fuse([
        FusionSignal("dfir", "network", "Observed flow", 0.9, 0.7, ["FLOW:1"], ["ip:1"], [], []),
        FusionSignal("identity", "identity", "Privilege path", 0.8, 0.8, ["PRIV:1"], ["user:a"], ["Known service account"], ["No endpoint memory"]),
    ])
    assert result["version"] == "X9.0"
    assert "Known service account" in result["contradictions"]
    assert "No endpoint memory" in result["gaps"]
    assert result["policy"]["automatic_remediation"] is False


def test_x10_policy_requires_human_approval_for_validation(tmp_path):
    store = ControlPlaneStore(tmp_path / "control.db")
    store.upsert(TenantPolicy(
        tenant_id="TENANT-1",
        name="Tenant",
        allowed_action_classes=["analysis", "validation"],
        maximum_autonomy="validation",
        require_human_approval=True,
    ))
    read = store.authorize("TENANT-1", action_class="analysis", requested_autonomy="analysis", actor="tester")
    assert read["allowed"] is True
    validation = store.authorize("TENANT-1", action_class="validation", requested_autonomy="validation", actor="tester")
    assert validation["allowed"] is False
    assert validation["reason"] == "human-approval-required"
    assert store.audit("TENANT-1")
