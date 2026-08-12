from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_sigma_tag_creates_high_confidence_attack_candidate(tmp_path):
    case_dir = tmp_path / "case"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T20:00:00+00:00",
        source="evtx",
        event_type="process",
        summary="Process creation",
        details={
            "Image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA",
            "event_id": "4688",
        },
        evidence_id="E0005",
    ))

    result = AttackMappingEngine(case_dir).analyze(max_candidates=20)
    tagged = [c for c in result["candidates"] if c["technique_id"] == "T1059.001"]
    assert tagged
    assert any(c["confidence"] == "high" and "Sigma rule" in c["reason"] for c in tagged)
