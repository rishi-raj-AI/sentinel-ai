from app.forensics.case_copilot_v4 import CaseCopilot, CopilotSource


class QueueProvider:
    configured = True
    model = "llama3.2:latest"
    configured_model = "R-Pilot"
    persisted_model = "llama3.2:latest"
    transport = "ollama-native"
    active_endpoint = "http://127.0.0.1:11434/api/chat"
    resolved_model = "llama3.2:latest"

    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def complete(self, system_prompt, user_prompt):
        self.calls += 1
        return self.answers.pop(0)


class FixedCopilot(CaseCopilot):
    def __init__(self, provider):
        self.provider = provider
        self.sigma_rules = "rules/sigma"
        self.case_dir = None
        self.timeline = None

    def retrieve(self, question, *, limit=12):
        return [
            CopilotSource(
                source_id="FLOW:1",
                kind="network",
                title="UDP flow",
                text="UDP 192.0.2.10:54000 -> 198.51.100.20:4444",
                evidence_id="E0003",
            ),
            CopilotSource(
                source_id="EVIDENCE:E0003",
                kind="evidence",
                title="E0003 sample.pcap",
                text="Registered packet capture",
                evidence_id="E0003",
            ),
        ][:limit]


def test_uncited_draft_gets_one_grounded_repair_pass():
    provider = QueueProvider([
        "The UDP 4444 flow warrants review because it is unusual.",
        "The UDP 4444 flow warrants review [FLOW:1, EVIDENCE:E0003].",
    ])
    result = FixedCopilot(provider).answer("Why review UDP 4444?")

    assert result["mode"] == "model"
    assert result["provider_error"] is None
    assert result["citation_repair_attempted"] is True
    assert provider.calls == 2
    assert "[FLOW:1" in result["answer"]
    assert result["citation_diagnostics_initial"]["cited_source_ids"] == []
    assert result["citation_diagnostics_final"]["unknown_source_ids"] == []


def test_invented_source_id_is_rejected_without_repair():
    provider = QueueProvider(["The flow is malicious [FLOW:999]."])
    result = FixedCopilot(provider).answer("Is it malicious?")

    assert result["mode"] == "deterministic"
    assert result["citation_repair_attempted"] is False
    assert provider.calls == 1
    assert "FLOW:999" in result["provider_error"]
    assert result["citation_diagnostics_initial"]["unknown_source_ids"] == ["FLOW:999"]
