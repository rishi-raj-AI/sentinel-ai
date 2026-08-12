from app.brain.planner import plan_command
from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.tools.forensics import _resolve_case_evidence


def test_volatility_evidence_planner_command():
    plan = plan_command("volatility evidence DFIR-2026-0001 E0001 windows.pslist")
    assert plan.steps[0].tool == "forensic.run_volatility_evidence"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "evidence_id": "E0001",
        "plugin": "windows.pslist",
    }


def test_registered_evidence_resolves_to_preserved_copy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    case = CaseManager().create_case("Memory workflow")
    source = tmp_path / "memory.raw"
    source.write_bytes(b"memory-image-test")

    item = EvidenceManager().register(case["case_id"], str(source))
    resolved = _resolve_case_evidence(case["case_id"], item["evidence_id"])
    verification = EvidenceManager().verify(case["case_id"], item["evidence_id"])

    assert resolved["evidence_id"] == item["evidence_id"]
    assert resolved["stored_path"] != str(source.resolve())
    assert verification["all_match"] is True
    assert verification["chain_of_custody_valid"] is True


def test_tampered_memory_evidence_fails_verification(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    case = CaseManager().create_case("Tampered memory workflow")
    source = tmp_path / "memory.raw"
    source.write_bytes(b"original-memory")

    item = EvidenceManager().register(case["case_id"], str(source))
    stored = _resolve_case_evidence(case["case_id"], item["evidence_id"])["stored_path"]
    with open(stored, "ab") as handle:
        handle.write(b"tampered")

    verification = EvidenceManager().verify(case["case_id"], item["evidence_id"])
    assert verification["all_match"] is False
