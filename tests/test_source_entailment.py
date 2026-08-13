from app.forensics.case_copilot import CopilotSource
from app.forensics.source_entailment import SourceAwareClaimVerifier


def _verifier():
    sources = [
        CopilotSource(
            source_id="TIMELINE:40",
            kind="timeline",
            title="searchpartyd event",
            text="timestamp=2026-08-12 source=macos summary=searchpartyd location update",
            metadata={"source": "macos", "event_type": "log"},
        ),
        CopilotSource(
            source_id="FLOW:1",
            kind="network",
            title="UDP 192.0.2.10:54000 -> 198.51.100.20:4444",
            text="Network flow protocol=UDP; src=192.0.2.10:54000; dst=198.51.100.20:4444; packets=1",
            metadata={"src": "192.0.2.10", "dst": "198.51.100.20", "dst_port": "4444"},
        ),
        CopilotSource(
            source_id="FLOW:2",
            kind="network",
            title="UDP 192.0.2.10:54001 -> 198.51.100.53:53",
            text="Network flow protocol=UDP; src=192.0.2.10:54001; dst=198.51.100.53:53; packets=1",
            metadata={"src": "192.0.2.10", "dst": "198.51.100.53", "dst_port": "53"},
        ),
        CopilotSource(
            source_id="SIGMA:sentinel-network-udp-4444:1",
            kind="sigma",
            title="Sentinel Unusual UDP Destination Port",
            text="Sigma detection level=medium evidence=E0003 tags=['sentinel.validation']",
            metadata={"rule_id": "sentinel-network-udp-4444", "level": "medium", "tags": ["sentinel.validation"]},
        ),
        CopilotSource(
            source_id="YARA:E0004:Sentinel_Test_Artifact",
            kind="yara",
            title="YARA Sentinel_Test_Artifact",
            text="YARA rule Sentinel_Test_Artifact matched evidence E0004 2 time(s)",
            metadata={"rule": "Sentinel_Test_Artifact", "match_count": 2},
        ),
        CopilotSource(
            source_id="BRIEF:CURRENT",
            kind="brief",
            title="Some evidence signals warrant focused review",
            text='{"confidence":"medium","collection_gaps":["No successfully parsed memory-forensics artifacts are present."]}',
            metadata={"confidence": "medium"},
        ),
    ]
    return SourceAwareClaimVerifier(sources)


def test_timeline_event_does_not_prove_normality():
    row = _verifier().verify_claim(
        "Searchpartyd logs indicate normal system activity [TIMELINE:40]."
    )
    assert row.status == "UNSUPPORTED"
    assert any("not that the activity was normal" in reason for reason in row.reasons)


def test_flow_proves_endpoints_but_not_malware():
    verifier = _verifier()
    supported = verifier.verify_claim(
        "UDP flow 192.0.2.10:54000 -> 198.51.100.20:4444 was observed [FLOW:1]."
    )
    assert supported.status == "SUPPORTED"

    unsupported = verifier.verify_claim(
        "The malware C2 flow used 192.0.2.10:54000 -> 198.51.100.20:4444 [FLOW:1]."
    )
    assert unsupported.status == "UNSUPPORTED"
    assert any("does not by itself establish malware" in reason for reason in unsupported.reasons)


def test_sigma_validation_rule_is_not_malware_specific():
    row = _verifier().verify_claim(
        "This is a malware-specific Sigma detection [SIGMA:sentinel-network-udp-4444:1]."
    )
    assert row.status == "UNSUPPORTED"
    assert any("does not identify this rule as malware-specific" in reason for reason in row.reasons)


def test_yara_test_rule_does_not_prove_malware_signature():
    row = _verifier().verify_claim(
        "The YARA hit indicates a malware signature [YARA:E0004:Sentinel_Test_Artifact]."
    )
    assert row.status == "UNSUPPORTED"
    assert any("does not establish that the rule is malware-specific" in reason for reason in row.reasons)


def test_brief_supports_recorded_memory_limitation():
    row = _verifier().verify_claim(
        "No successfully parsed memory-forensics artifacts are present [BRIEF:CURRENT]."
    )
    assert row.claim_type == "LIMITATION"
    assert row.status == "SUPPORTED"
    assert row.support_score == 1.0


def test_answer_audit_includes_source_type_checks():
    result = _verifier().verify_answer(
        "UDP flow 192.0.2.10:54000 -> 198.51.100.20:4444 was observed [FLOW:1].\n"
        "Searchpartyd logs indicate normal system activity [TIMELINE:40]."
    )
    assert result["policy"]["source_type_aware_entailment"] is True
    assert result["policy"]["lexical_overlap_secondary_only"] is True
    assert result["unsupported_claim_count"] == 1
    assert result["source_type_entailment"]


def test_adjacent_citation_line_is_bound_to_preceding_claim():
    result = _verifier().verify_answer(
        "Two UDP flows were observed from 192.0.2.10.\n"
        "[FLOW:2, FLOW:1]"
    )
    assert result["adjacent_citation_bindings"] == 1
    assert result["claim_count"] == 1
    assert result["claims"][0]["source_ids"] == ["FLOW:2", "FLOW:1"]
    assert "[FLOW:2, FLOW:1]" in result["answer"]
