from app.forensics.case_copilot import CopilotSource
from app.forensics.source_entailment_v2 import SourceAwareClaimVerifier


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
            source_id="TIMELINE:32",
            kind="timeline",
            title="locationd event",
            text="timestamp=2026-08-12 source=macos summary=locationd location service update",
            metadata={"source": "macos", "event_type": "log"},
        ),
        CopilotSource(
            source_id="FLOW:1",
            kind="network",
            title="UDP 192.0.2.10:54000 -> 198.51.100.20:4444",
            text="Network flow protocol=UDP; src=192.0.2.10:54000; dst=198.51.100.20:4444; packets=1; evidence=['E0003']",
            evidence_id="E0003",
            metadata={"src": "192.0.2.10", "src_port": "54000", "dst": "198.51.100.20", "dst_port": "4444", "packets": 1, "evidence_id": "E0003"},
        ),
        CopilotSource(
            source_id="FLOW:2",
            kind="network",
            title="UDP 192.0.2.10:54001 -> 198.51.100.53:53",
            text="Network flow protocol=UDP; src=192.0.2.10:54001; dst=198.51.100.53:53; packets=1; evidence=['E0003']",
            evidence_id="E0003",
            metadata={"src": "192.0.2.10", "src_port": "54001", "dst": "198.51.100.53", "dst_port": "53", "packets": 1, "evidence_id": "E0003"},
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


def test_normal_system_operations_phrase_is_also_rejected():
    row = _verifier().verify_claim(
        "Locationd and Searchpartyd logs are likely related to normal system operations [TIMELINE:32, TIMELINE:40]."
    )
    assert row.status == "UNSUPPORTED"
    assert row.claim_type == "INFERRED"
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


def test_multi_flow_claim_uses_union_of_cited_flow_facts():
    verifier = _verifier()
    row = verifier.verify_claim(
        "Two UDP flows were observed: 192.0.2.10:54000 -> 198.51.100.20:4444 and "
        "192.0.2.10:54001 -> 198.51.100.53:53 [FLOW:1, FLOW:2]."
    )
    assert row.status == "SUPPORTED"
    result = verifier.verify_answer(
        "Two UDP flows were observed: 192.0.2.10:54000 -> 198.51.100.20:4444 and "
        "192.0.2.10:54001 -> 198.51.100.53:53 [FLOW:1, FLOW:2]."
    )
    aggregate = [
        check
        for item in result["source_type_entailment"]
        for check in item["checks"]
        if check["source_id"] == "FLOW:AGGREGATE"
    ]
    assert aggregate
    detail = aggregate[0]["detail"]
    assert aggregate[0]["entailed"] is True
    assert detail["missing_ips"] == []
    assert detail["missing_ports"] == []
    assert detail["asserted_ports"] == ["54000", "4444", "54001", "53"]
    assert "1" not in detail["asserted_ports"] and "2" not in detail["asserted_ports"]
    assert detail["citations_removed_before_fact_extraction"] is True


def test_multi_flow_claim_rejects_fact_missing_from_all_cited_flows():
    row = _verifier().verify_claim(
        "Two UDP flows were observed, including 203.0.113.77:9999 [FLOW:1, FLOW:2]."
    )
    assert row.status == "UNSUPPORTED"
    assert any("not present in any cited flow source" in reason for reason in row.reasons)


def test_flow_packet_count_and_evidence_association_are_verified():
    verifier = _verifier()
    row = verifier.verify_claim(
        "The cited flows each have a low packet count and are associated with evidence E0003 [FLOW:1, FLOW:2]."
    )
    assert row.status == "SUPPORTED"
    result = verifier.verify_answer(
        "The cited flows each have a low packet count and are associated with evidence E0003 [FLOW:1, FLOW:2]."
    )
    aggregate = result["source_type_entailment"][0]["checks"][0]
    detail = aggregate["detail"]
    assert detail["source_packet_counts"] == {"FLOW:1": 1, "FLOW:2": 1}
    assert detail["low_packet_claimed"] is True
    assert detail["low_packet_supported"] is True
    assert detail["asserted_evidence_ids"] == ["E0003"]
    assert detail["missing_evidence_ids"] == []
    assert result["policy"]["structured_fact_entailment_precedes_lexical_similarity"] is True


def test_wrong_packet_count_or_evidence_association_is_rejected():
    verifier = _verifier()
    packet = verifier.verify_claim(
        "The flows contain 99 packets [FLOW:1, FLOW:2]."
    )
    assert packet.status == "UNSUPPORTED"
    assert any("packet count 99" in reason for reason in packet.reasons)

    evidence = verifier.verify_claim(
        "The flows are associated with evidence E9999 [FLOW:1, FLOW:2]."
    )
    assert evidence.status == "UNSUPPORTED"
    assert any("evidence association E9999" in reason for reason in evidence.reasons)


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
    assert result["policy"]["multi_source_fact_union"] is True
    assert result["policy"]["benign_interpretation_requires_explicit_support"] is True
    assert result["policy"]["citations_removed_before_network_fact_extraction"] is True
    assert result["policy"]["packet_count_facts_verified"] is True
    assert result["policy"]["flow_evidence_associations_verified"] is True
    assert result["policy"]["structured_fact_entailment_precedes_lexical_similarity"] is True
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
