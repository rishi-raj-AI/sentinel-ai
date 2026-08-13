from pathlib import Path

from app.enterprise.core import InvestigationReasoningService
from app.forensics.case_copilot import CopilotSource
from app.forensics.case_copilot_v5 import CaseCopilot


def _brief_source():
    return CopilotSource(
        source_id="BRIEF:CURRENT",
        kind="brief",
        title="Current case brief",
        text='{"headline":"Review required","confidence":"medium","collection_gaps":["No memory"],"recommended_actions":["Acquire memory"],"hypotheses":[]}',
        metadata={"confidence": "medium"},
    )


def test_brief_section_aliases_are_retrieved_section_bound():
    source = _brief_source()
    normalized = CaseCopilot._normalize_citations(
        "Review gaps [BRIEF:CURRENT:COLLECTION_GAPS] and actions [BRIEF:CURRENT:RECOMMENDED_ACTIONS].",
        [source],
    )
    assert normalized.count("[BRIEF:CURRENT]") == 2
    aliases = CaseCopilot._brief_aliases([source])
    assert "brief:current:collection_gaps" in aliases
    assert "brief:current:recommended_actions" in aliases


def test_unknown_or_empty_brief_section_is_not_canonicalized():
    source = _brief_source()
    normalized = CaseCopilot._normalize_citations(
        "Unsupported [BRIEF:CURRENT:MALWARE_VERDICT] and empty [BRIEF:CURRENT:HYPOTHESES].",
        [source],
    )
    assert "BRIEF:CURRENT:MALWARE_VERDICT" in normalized
    assert "BRIEF:CURRENT:HYPOTHESES" in normalized
    assert CaseCopilot._citations_are_grounded(normalized, [source]) is False


def test_counter_evidence_ranks_direct_forensic_context_over_generic_events(tmp_path):
    service = InvestigationReasoningService(tmp_path)
    service.graph_service.snapshot = lambda **kwargs: {
        "nodes": [
            {
                "id": "event:generic",
                "type": "event",
                "label": "Normal system activity",
                "attributes": {"summary": "routine system service event"},
            },
            {
                "id": "yara_rule:Sentinel_Test_Artifact",
                "type": "yara_rule",
                "label": "Sentinel Test Artifact",
                "attributes": {"tags": ["validation"], "evidence_id": "E0004"},
            },
            {
                "id": "evidence:E0004",
                "type": "evidence",
                "label": "E0004 yara-test-artifact.txt",
                "attributes": {"filename": "yara-test-artifact.txt"},
            },
        ]
    }
    rows = service.counter_evidence(["test", "validation", "system", "normal"], limit=10)
    assert rows
    assert rows[0]["id"] == "yara_rule:Sentinel_Test_Artifact"
    generic = next(row for row in rows if row["id"] == "event:generic")
    assert rows[0]["relevance_score"] > generic["relevance_score"]
    assert generic["relevance_components"]["generic_event_suppressed"] is True


def test_counter_evidence_returns_auditable_ranking_fields(tmp_path):
    service = InvestigationReasoningService(tmp_path)
    service.graph_service.snapshot = lambda **kwargs: {
        "nodes": [
            {"id": "evidence:E0004", "type": "evidence", "label": "test artifact", "attributes": {"validation": True}},
        ]
    }
    row = service.counter_evidence(["test", "validation"], limit=1)[0]
    assert row["relevance_score"] > 0
    assert set(row["matched_terms"]) == {"test", "validation"}
    assert "node_type_weight" in row["relevance_components"]
