from app.brain.planner import plan_command
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.forensics.yara_adapter import YaraAdapter


def test_yara_parser_extracts_rule_and_string():
    output = "Sentinel_Test_Artifact /tmp/evidence.txt\n0x10:$marker: SENTINEL_YARA_TEST_MARKER\n"
    matches = YaraAdapter._parse_output(output)
    assert len(matches) == 1
    assert matches[0]["rule"] == "Sentinel_Test_Artifact"
    assert matches[0]["strings"] == ["0x10:$marker: SENTINEL_YARA_TEST_MARKER"]


def test_yara_planner_commands():
    status = plan_command("yara status")
    assert status.steps[0].tool == "forensic.yara_status"

    scan = plan_command("yara evidence DFIR-2026-0001 E0004 rules/sentinel_test.yar")
    assert scan.steps[0].tool == "forensic.yara_scan_evidence"
    assert scan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "evidence_id": "E0004",
        "rule_path": "rules/sentinel_test.yar",
    }


def test_yara_match_becomes_graph_entity(tmp_path):
    case_dir = tmp_path / "DFIR-YARA"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T21:00:00+00:00",
        source="yara",
        event_type="yara_match",
        summary="YARA match: Sentinel_Test_Artifact",
        details={
            "rule": "Sentinel_Test_Artifact",
            "tags": [],
            "metadata": {},
            "evidence_path": "/tmp/evidence.txt",
            "rule_path": "rules/sentinel_test.yar",
        },
        evidence_id="E0004",
    ))

    graph = EvidenceGraphEngine(case_dir).build(max_nodes=100, max_edges=100)
    assert graph["summary"]["nodes_by_type"]["yara_rule"] == 1
    assert graph["summary"]["edges_by_relation"]["matched_rule"] == 1
    assert graph["summary"]["edges_by_relation"]["matched"] == 1
