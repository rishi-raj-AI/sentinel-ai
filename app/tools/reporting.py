from __future__ import annotations

from app.forensics.case_manager import CaseManager
from app.forensics.reporting import ForensicReportExporter


def export_case_report(
    case_id: str,
    output_format: str = "all",
    report_name: str | None = None,
    max_items: int = 50,
):
    manager = CaseManager()
    manager.load_case(case_id)
    case_dir = manager.root / case_id
    return ForensicReportExporter(case_dir).export(
        output_format=output_format,
        report_name=report_name,
        max_items=max_items,
    )
