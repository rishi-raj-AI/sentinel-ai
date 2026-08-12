from __future__ import annotations

import hashlib
import json
from pathlib import Path

from app.forensics.case_manager import CaseManager
from app.forensics.reporting import ForensicReportExporter


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def verify_case_report(case_id: str, report_name: str):
    manager = CaseManager()
    manager.load_case(case_id)
    reports_dir = manager.root / case_id / "reports"
    stem = ForensicReportExporter._slug(report_name)
    manifest_path = reports_dir / f"{stem}.manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Report manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checks = []
    for item in manifest.get("outputs", []):
        path = Path(str(item.get("path") or ""))
        exists = path.is_file()
        actual_sha256 = _sha256(path) if exists else None
        expected_sha256 = item.get("sha256")
        checks.append({
            "format": item.get("format"),
            "path": str(path),
            "exists": exists,
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
            "match": exists and actual_sha256 == expected_sha256,
        })

    return {
        "case_id": case_id,
        "report_name": stem,
        "manifest_path": str(manifest_path.resolve()),
        "manifest_sha256": _sha256(manifest_path),
        "outputs": checks,
        "all_match": bool(checks) and all(item["match"] for item in checks),
    }
