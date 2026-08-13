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


class _Provider:
    configured = True
    model = "test-model"
    configured_model = "test-model"
    persisted_model = "test-model"
    transport = "test"
    active_endpoint = "test://local"
    resolved_model = None

    def __init__(self):
        self.calls = 0

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        self.calls += 1
        if self.calls == 1:
            return "The test artifact warrants review without citations."
        return (
            "The YARA test artifact should be reviewed "
            "[YARA:E0004:Sentinel_Test_Artifact] using "
            "[EVIDENCE:E0004_yara-test-artifact.txt]."
        )


class _Copilot(CaseCopilot):
    def retrieve(self, question: str, *, limit: int = 12):
        return _sources()[:limit]


def test_full_repair_path_enters_model_mode_and_audits_provenance(tmp_path):
    provider = _Provider()
    result = _Copilot(tmp_path, provider=provider).answer("Assess the YARA match")
    assert provider.calls == 2
    assert result["mode"] == "model"
    assert result["provider_error"] is None
    assert result["citation_repair_attempted"] is True
    assert "[EVIDENCE:E0004]" in result["answer"]
    assert result["provenance_repair_count"] == 1
    assert result["provenance_repairs_repair_pass"][0]["basis"] == "retrieved_evidence_filename_metadata"
    assert result["grounding_policy"] == {
        "unknown_source_ids_rejected": True,
        "metadata_bound_aliases_only": True,
        "provenance_repairs_audited": True,
    }
