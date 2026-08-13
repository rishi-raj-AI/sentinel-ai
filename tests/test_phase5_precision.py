from pathlib import Path

from app.enterprise.reasoning_v2 import InvestigationReasoningService
from app.soc.core_v2 import SOCSupervisor


def test_generic_event_is_heavily_penalized_below_test_context(tmp_path):
    service = InvestigationReasoningService(tmp_path)
    service.graph_service.snapshot = lambda **kwargs: {
        "nodes": [
            {
                "id": "event:bluetooth",
                "type": "event",
                "label": "bluetoothd system update event",
                "attributes": {"summary": "normal system service update"},
            },
            {
                "id": "yara_rule:Sentinel_Test_Artifact",
                "type": "yara_rule",
                "label": "Sentinel Test Artifact",
                "attributes": {"validation": True},
            },
            {
                "id": "evidence:E0004",
                "type": "evidence",
                "label": "E0004 yara-test-artifact.txt",
                "attributes": {"validation": True},
            },
        ]
    }
    rows = service.counter_evidence(["test", "validation", "update", "system", "normal"], limit=10)
    assert rows[0]["id"] == "yara_rule:Sentinel_Test_Artifact"
    generic = next(row for row in rows if row["id"] == "event:bluetooth")
    assert rows[0]["relevance_score"] > generic["relevance_score"]
    assert generic["relevance_components"]["phase5_precision_rerank"] is True


def test_counter_evidence_confidence_uses_quality_not_candidate_count(tmp_path):
    service = InvestigationReasoningService(tmp_path)
    weak = [
        {"id": f"event:{i}", "type": "event", "relevance_score": 0.2}
        for i in range(40)
    ]
    strong = [
        {"id": "yara:test", "type": "yara_rule", "relevance_score": 10.0},
        {"id": "evidence:E0004", "type": "evidence", "relevance_score": 8.0},
    ]
    weak_conf, weak_detail = service.counter_evidence_confidence(weak)
    strong_conf, strong_detail = service.counter_evidence_confidence(strong)
    assert weak_conf < 0.3
    assert strong_conf > weak_conf
    assert weak_detail["candidate_count"] == 40
    assert weak_detail["method"] == "weighted_top_relevance"
    assert strong_detail["mean_top_score"] > weak_detail["mean_top_score"]


def test_supervisor_contract_forbids_speculative_gap_and_detection_inferences():
    rules = SOCSupervisor.STRICT_SYNTHESIS_RULES.casefold()
    assert "never infer malware absence, presence, infection state, or evasion" in rules
    assert "does not by itself indicate malware" in rules
    assert "test/validation-named rule must not be described as a malware signature" in rules
    assert "never cite agent names" in rules
    assert "use only retrieved sentinel source ids as citations" in rules


def test_phase5_1_version_and_precision_agent_registration():
    assert SOCSupervisor.VERSION == "5.1"
    names = [agent.name for agent in SOCSupervisor.AGENT_TYPES]
    assert names[-1] == "counter-evidence-agent"
