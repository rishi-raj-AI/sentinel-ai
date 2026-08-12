from pathlib import Path

from app.brain.planner_ext import plan_command
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_sigma_engine_matches_udp_4444(tmp_path: Path):
    case_dir = tmp_path / "case"
    TimelineStore(case_dir).append(
        TimelineEvent(
            timestamp="2026-01-01T00:00:00+00:00",
            source="tshark",
            event_type="network",
            summary="test flow",
            details={"src": "192.0.2.10", "dst": "198.51.100.20", "udp_dstport": "4444"},
            evidence_id="E0001",
        )
    )
    rule = tmp_path / "rule.yml"
    rule.write_text(
        """title: UDP Test\nid: udp-test\nlogsource:\n  category: network_connection\ndetection:\n  selection:\n    DestinationPort: '4444'\n  condition: selection\nlevel: medium\n""",
        encoding="utf-8",
    )
    result = SigmaEngine(case_dir).analyze(str(rule))
    assert result["detection_count"] == 1
    assert result["detections"][0]["rule_id"] == "udp-test"


def test_sigma_engine_contains_and_endswith(tmp_path: Path):
    case_dir = tmp_path / "case"
    TimelineStore(case_dir).append(
        TimelineEvent(
            timestamp="2026-01-01T00:00:00+00:00",
            source="evtx",
            event_type="process",
            summary="PowerShell",
            details={"Image": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -enc AAAA"},
            evidence_id="E0002",
        )
    )
    rule = tmp_path / "rule.yml"
    rule.write_text(
        """title: Encoded PowerShell\nid: ps-enc\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  image:\n    Image|endswith: '\\\\powershell.exe'\n  encoded:\n    CommandLine|contains: ' -enc '\n  condition: image and encoded\nlevel: high\n""",
        encoding="utf-8",
    )
    result = SigmaEngine(case_dir).analyze(str(rule))
    assert result["detection_count"] == 1
    assert result["summary"]["by_level"]["high"] == 1


def test_sigma_planner_extension():
    plan = plan_command("sigma analyze DFIR-2026-0001 rules/sigma 25")
    assert plan.intent == "sigma_analyze"
    assert plan.steps[0].tool == "forensic.sigma_analyze"
    assert plan.steps[0].arguments["max_detections"] == 25
