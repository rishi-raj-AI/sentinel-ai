from app.forensics.case_copilot import CopilotSource
from app.forensics.case_copilot_v6 import CaseCopilot
from app.forensics.claim_verifier import ClaimEvidenceVerifier


def _sources():
    return [
        CopilotSource(
            source_id="YARA:E0004:Sentinel_Test_Artifact",
            kind="yara",
            title="YARA Sentinel_Test_Artifact",
            text="YARA rule Sentinel_Test_Artifact matched evidence E0004 2 time(s); first_seen=21:18:51 last_seen=21:19:04",
            evidence_id="E0004",
            metadata={"rule": "Sentinel_Test_Artifact", "match_count": 2},
        ),
        CopilotSource(
            source_id="SIGMA:sentinel-network-udp-4444:1",
            kind="sigma",
            title="Sentinel Unusual UDP Destination Port",
            text="Sigma detection level=medium evidence=E0003 matched=['selection'] tags=['sentinel.validation']",
            evidence_id="E0003",
            metadata={"rule_id": "sentinel-network-udp-4444", "level": "medium", "tags": ["sentinel.validation"]},
        ),
        CopilotSource(
            source_id="FLOW:1",
            kind="network",
            title="UDP 192.0.2.10:54000 -> 198.51.100.20:4444",
            text="Network flow protocol=UDP; src=192.0.2.10:54000; dst=198.51.100.20:4444; packets=1; evidence=['E0003']",
            evidence_id="E0003",
        ),
    ]


def test_direct_yara_observation_is_supported():
    verifier = ClaimEvidenceVerifier(_sources())
    result = verifier.verify_claim(
        "YARA rule Sentinel_Test_Artifact matched evidence E0004 twice [YARA:E0004:Sentinel_Test_Artifact]."
    )
    assert result.status == "SUPPORTED"
    assert result.claim_type == "OBSERVED"


def test_yara_timing_does_not_prove_recent_scan_or_update():
    verifier = ClaimEvidenceVerifier(_sources())
    result = verifier.verify_claim(
        "This suggests that the system was recently scanned or updated with this rule [YARA:E0004:Sentinel_Test_Artifact]."
    )
    assert result.status == "UNSUPPORTED"
    assert result.claim_type == "INFERRED"
    assert any("does not establish" in reason for reason in result.reasons)


def test_validation_sigma_rule_cannot_be_called_malware_specific():
    verifier = ClaimEvidenceVerifier(_sources())
    result = verifier.verify_claim(
        "Malware-specific Sigma detection matched E0003 [SIGMA:sentinel-network-udp-4444:1]."
    )
    assert result.status == "UNSUPPORTED"
    assert any("malware-specific" in reason for reason in result.reasons)


def test_recommendation_is_allowed_without_entailment():
    verifier = ClaimEvidenceVerifier(_sources())
    result = verifier.verify_claim("Acquire an authorized memory image and run Volatility plugins.")
    assert result.status == "SUPPORTED"
    assert result.claim_type == "RECOMMENDATION"


def test_answer_verifier_removes_unsupported_claims():
    verifier = ClaimEvidenceVerifier(_sources())
    result = verifier.verify_answer(
        "**Findings**\n"
        "- UDP flow reached destination port 4444 [FLOW:1].\n"
        "- Malware-specific Sigma detection matched E0003 [SIGMA:sentinel-network-udp-4444:1].\n"
        "\n**Next Actions**\n"
        "- Acquire an authorized memory image."
    )
    assert "UDP flow reached destination port 4444" in result["answer"]
    assert "Malware-specific" not in result["answer"]
    assert "Acquire an authorized memory image" in result["answer"]
    assert result["unsupported_claim_count"] == 1


class FakeProvider:
    configured = True
    model = "test-model"
    configured_model = "test-model"
    persisted_model = "test-model"
    transport = "test"
    active_endpoint = "test://model"
    resolved_model = None

    def __init__(self, answer):
        self._answer = answer

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return self._answer


class TestCopilot(CaseCopilot):
    def __init__(self, provider):
        self.provider = provider
        self.sigma_rules = "rules/sigma"
        self.case_dir = None
        self.timeline = None

    def retrieve(self, question: str, *, limit: int = 12):
        return _sources()


def test_copilot_keeps_model_mode_when_half_or_more_factual_claims_survive():
    answer = (
        "**Findings**\n"
        "- UDP flow reached destination port 4444 [FLOW:1].\n"
        "- Malware-specific Sigma detection matched E0003 [SIGMA:sentinel-network-udp-4444:1].\n"
        "**Next Actions**\n"
        "- Acquire an authorized memory image."
    )
    result = TestCopilot(FakeProvider(answer)).answer("Assess current findings")
    assert result["mode"] == "model"
    assert result["claim_verification_applied"] is True
    assert result["claim_verification"]["factual_claim_support_ratio"] >= 0.5
    assert "Malware-specific" not in result["answer"]
    assert result["model_answer_rejected_by_claim_verifier"] is False


def test_copilot_falls_back_when_model_factual_support_is_too_weak():
    answer = (
        "- UDP flow reached destination port 4444 [FLOW:1].\n"
        "- Malware-specific Sigma detection matched E0003 [SIGMA:sentinel-network-udp-4444:1].\n"
        "- This suggests that the system was recently scanned or updated with this rule [YARA:E0004:Sentinel_Test_Artifact]."
    )
    result = TestCopilot(FakeProvider(answer)).answer("Assess current findings")
    assert result["mode"] == "deterministic"
    assert result["model_answer_rejected_by_claim_verifier"] is True
    assert "claim_verifier_fallback" in result["provider_error"]
