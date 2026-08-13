from app.forensics.case_copilot_v5 import CaseCopilot, CopilotSource


def _sources(filename="E0004_yara-test-artifact.txt"):
    return [
        CopilotSource(
            source_id="EVIDENCE:E0004",
            kind="evidence",
            title=f"E0004 {filename}",
            text="Registered evidence E0004",
            evidence_id="E0004",
            metadata={"filename": filename, "sha256": "a" * 64},
        ),
        CopilotSource(
            source_id="YARA:E0004:Sentinel_Test_Artifact",
            kind="yara",
            title="YARA Sentinel_Test_Artifact",
            text="YARA rule matched E0004",
            evidence_id="E0004",
        ),
        CopilotSource(
            source_id="FLOW:1",
            kind="network",
            title="UDP flow",
            text="UDP flow to port 4444",
            evidence_id="E0003",
        ),
    ]


def test_metadata_bound_evidence_filename_alias_is_canonicalized():
    sources = _sources()
    answer = "Review [EVIDENCE:E0004_yara-test-artifact.txt] with [YARA:E0004:Sentinel_Test_Artifact]."
    normalized = CaseCopilot._normalize_citations(answer, sources)
    assert "[EVIDENCE:E0004]" in normalized
    assert "E0004_yara-test-artifact.txt" not in normalized
    assert CaseCopilot._citations_are_grounded(normalized, sources) is True


def test_filename_without_preservation_prefix_is_bound_to_same_evidence():
    sources = _sources("yara-test-artifact.txt")
    answer = "Review EVIDENCE:E0004_yara-test-artifact.txt."
    normalized = CaseCopilot._normalize_citations(answer, sources)
    assert normalized == "Review [EVIDENCE:E0004]."
    assert CaseCopilot._citations_are_grounded(normalized, sources) is True


def test_wrong_filename_is_not_repaired():
    sources = _sources()
    answer = "Review [EVIDENCE:E0004_malware.exe]."
    normalized = CaseCopilot._normalize_citations(answer, sources)
    assert "EVIDENCE:E0004_malware.exe" in normalized
    assert CaseCopilot._citations_are_grounded(normalized, sources) is False


def test_wrong_evidence_id_is_not_repaired():
    sources = _sources()
    answer = "Review [EVIDENCE:E9999_yara-test-artifact.txt]."
    normalized = CaseCopilot._normalize_citations(answer, sources)
    assert "EVIDENCE:E9999_yara-test-artifact.txt" in normalized
    assert CaseCopilot._citations_are_grounded(normalized, sources) is False


def test_path_injection_is_not_treated_as_metadata_alias():
    sources = _sources()
    answer = "Review [EVIDENCE:E0004_../../yara-test-artifact.txt]."
    normalized = CaseCopilot._normalize_citations(answer, sources)
    assert "../../" in normalized
    assert CaseCopilot._citations_are_grounded(normalized, sources) is False


def test_provenance_repair_records_metadata_basis():
    sources = _sources()
    repaired, repairs = CaseCopilot._canonicalize_evidence_aliases(
        "Use EVIDENCE:E0004_yara-test-artifact.txt for context.", sources
    )
    assert repaired == "Use EVIDENCE:E0004 for context."
    assert repairs == [{
        "original": "EVIDENCE:E0004_yara-test-artifact.txt",
        "canonical": "EVIDENCE:E0004",
        "basis": "retrieved_evidence_filename_metadata",
    }]
