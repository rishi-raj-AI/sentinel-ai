from pathlib import Path

from app.brain.planner_ext import plan_command
from app.forensics.case_manager import CaseManager
from app.forensics.evidence import EvidenceManager
from app.forensics.reporting import ForensicReportExporter
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_report_export_generates_all_formats_with_hashes(tmp_path):
    cases_root = tmp_path / "cases"
    manager = CaseManager(str(cases_root))
    case = manager.create_case("Reporting integration test")
    case_id = case["case_id"]
    case_dir = cases_root / case_id

    source = tmp_path / "evidence.txt"
    source.write_text("sentinel report evidence", encoding="utf-8")
    EvidenceManager(str(cases_root)).register(case_id, str(source))

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

    result = ForensicReportExporter(case_dir).export(
        output_format="all",
        report_name="integration-report",
        max_items=20,
    )

    assert result["evidence_integrity"]["all_match"] is True
    assert result["evidence_integrity"]["chain_of_custody_valid"] is True
    assert {item["format"] for item in result["outputs"]} == {"json", "markdown", "html", "pdf"}

    for item in result["outputs"]:
        path = Path(item["path"])
        assert path.is_file()
        assert path.stat().st_size == item["size_bytes"]
        assert len(item["sha256"]) == 64

    pdf = next(Path(item["path"]) for item in result["outputs"] if item["format"] == "pdf")
    assert pdf.read_bytes().startswith(b"%PDF-")

    html = next(Path(item["path"]) for item in result["outputs"] if item["format"] == "html")
    assert "Sentinel Forensic Investigation Report" in html.read_text(encoding="utf-8")

    manifest = Path(result["manifest"]["path"])
    assert manifest.is_file()
    assert len(result["manifest"]["sha256"]) == 64


def test_report_export_planner_route():
    plan = plan_command("export report DFIR-2026-0001 all 50 final-report")
    assert plan.steps[0].tool == "forensic.export_case_report"
    assert plan.steps[0].arguments["case_id"] == "DFIR-2026-0001"
    assert plan.steps[0].arguments["output_format"] == "all"
    assert plan.steps[0].arguments["max_items"] == 50
    assert plan.steps[0].arguments["report_name"] == "final-report"
