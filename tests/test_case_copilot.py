from app.brain.planner_ext import plan_command
from app.forensics.case_copilot import CaseCopilot
from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.timeline import TimelineEvent, TimelineStore


def _case(tmp_path):
    cases_root = tmp_path / "cases"
    manager = CaseManager(str(cases_root))
    case = manager.create_case("Copilot integration test")
    case_id = case["case_id"]
    case_dir = cases_root / case_id
    evidence = tmp_path / "capture.pcap"
    evidence.write_bytes(b"pcap-test")
    EvidenceManager(str(cases_root)).register(case_id, str(evidence))
    TimelineStore(case_dir).append(TimelineEvent(
        timestamp="2026-08-12T19:30:08+00:00",
        source="tshark",
        event_type="network",
        summary="192.0.2.10 -> 198.51.100.20",
        details={
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "udp_srcport": "54000",
            "udp_dstport": "4444",
            "protocols": "eth:ip:udp:data",
        },
        evidence_id="E0001",
    ))
    return case_dir, case_id


class FakeProvider:
    configured = True
    model = "test-model"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        assert "Answer only from the supplied case sources" in system_prompt
        assert "4444" in user_prompt
        assert "SOURCE" in user_prompt
        return "UDP/4444 is supported by the captured network flow [FLOW:1]."


class BrokenProvider(FakeProvider):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        raise RuntimeError("offline")


class UngroundedProvider(FakeProvider):
    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return "This is definitely malicious."


def test_copilot_retrieves_network_evidence(tmp_path):
    case_dir, _ = _case(tmp_path)
    copilot = CaseCopilot(case_dir)
    sources = copilot.retrieve("Why should I review UDP port 4444?", limit=8)
    assert any(source.kind == "network" and "4444" in source.text for source in sources)
    assert any(source.evidence_id == "E0001" for source in sources)


def test_copilot_model_mode_is_grounded(tmp_path):
    case_dir, _ = _case(tmp_path)
    result = CaseCopilot(case_dir, provider=FakeProvider()).answer("Why is port 4444 worth reviewing?")
    assert result["mode"] == "model"
    assert result["model"] == "test-model"
    assert "[FLOW:1]" in result["answer"]
    assert any(source["source_id"] == "FLOW:1" for source in result["sources"])
    assert result["provider_error"] is None


def test_copilot_model_failure_falls_back(tmp_path):
    case_dir, _ = _case(tmp_path)
    result = CaseCopilot(case_dir, provider=BrokenProvider()).answer("What network activity matters?")
    assert result["mode"] == "deterministic"
    assert "currently ingested case evidence" in result["answer"]
    assert "model_fallback" in result["provider_error"]
    assert result["source_count"] > 0


def test_copilot_rejects_uncited_model_answer(tmp_path):
    case_dir, _ = _case(tmp_path)
    result = CaseCopilot(case_dir, provider=UngroundedProvider()).answer("Is this malicious?")
    assert result["mode"] == "deterministic"
    assert "no Sentinel source citations" in result["provider_error"]


def test_planner_routes_copilot_commands():
    status = plan_command("copilot status")
    assert status.steps[0].tool == "forensic.copilot_status"
    ask = plan_command("copilot ask DFIR-2026-0001 Why is UDP 4444 unusual?")
    assert ask.steps[0].tool == "forensic.copilot_ask"
    assert ask.steps[0].arguments["case_id"] == "DFIR-2026-0001"
    assert "4444" in ask.steps[0].arguments["question"]