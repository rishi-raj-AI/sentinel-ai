from __future__ import annotations

import hashlib
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.evidence import EvidenceManager
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.investigation import InvestigationEngine
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.threat_intel import ThreatIntelEngine
from app.forensics.timeline import TimelineStore


class ForensicReportExporter:
    """Build and export an investigator-facing forensic case report.

    Exports are derived from the preserved case state and never modify evidence.
    Generated files are written beneath the case's reports directory and each
    output is returned with its own SHA-256 digest.
    """

    FORMATS = {"json", "markdown", "html", "pdf", "all"}

    def __init__(self, case_dir: str | Path, *, sigma_rules: str = "rules/sigma") -> None:
        self.case_dir = Path(case_dir)
        self.sigma_rules = sigma_rules
        self.timeline = TimelineStore(case_dir)

    @staticmethod
    def _slug(value: str) -> str:
        text = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()).strip("-.")
        return text or "case-report"

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _case_record(self) -> dict[str, Any]:
        path = self.case_dir / "case.json"
        if not path.is_file():
            raise FileNotFoundError(f"Case metadata not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def build_report(self, *, max_items: int = 50) -> dict[str, Any]:
        if max_items < 1 or max_items > 500:
            raise ValueError("max_items must be between 1 and 500")

        case = self._case_record()
        case_id = str(case.get("case_id") or self.case_dir.name)
        brief = CaseReasoningEngine(self.case_dir, sigma_rules=self.sigma_rules).build(max_items=max_items)
        investigation = InvestigationEngine(self.case_dir).analyze(window_seconds=120, max_findings=max_items)
        sigma = SigmaEngine(self.case_dir).analyze(self.sigma_rules, max_detections=max_items)
        attack = AttackMappingEngine(self.case_dir).analyze(max_candidates=max_items)
        intel = ThreatIntelEngine(self.case_dir).inventory(max_items=max_items)
        graph = EvidenceGraphEngine(self.case_dir).build(max_nodes=5000, max_edges=10000)
        verification = EvidenceManager(str(self.case_dir.parent)).verify(case_id=case_id)

        evidence = []
        for item in case.get("evidence", []):
            evidence.append({
                "evidence_id": item.get("evidence_id"),
                "filename": item.get("filename"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
                "registered_at": item.get("registered_at"),
                "stored_path": item.get("stored_path"),
            })

        yara_events = [
            event for event in self.timeline.read()
            if event.get("source") == "yara" or event.get("event_type") == "yara_match"
        ]
        yara_groups: dict[tuple[str, str], dict[str, Any]] = {}
        for event in yara_events:
            details = event.get("details") or {}
            key = (str(event.get("evidence_id") or ""), str(details.get("rule") or "unknown"))
            group = yara_groups.setdefault(key, {
                "evidence_id": event.get("evidence_id"),
                "rule": details.get("rule"),
                "match_count": 0,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
            })
            group["match_count"] += 1
            stamp = event.get("timestamp")
            if stamp and (not group["first_seen"] or stamp < group["first_seen"]):
                group["first_seen"] = stamp
            if stamp and (not group["last_seen"] or stamp > group["last_seen"]):
                group["last_seen"] = stamp

        return {
            "report": {
                "schema": "sentinel-forensic-report-v1",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "case_id": case_id,
                "title": case.get("title"),
                "description": case.get("description"),
                "case_status": case.get("status"),
                "case_created_at": case.get("created_at"),
            },
            "executive_summary": brief,
            "evidence_integrity": verification,
            "evidence_inventory": evidence,
            "sigma": {
                "summary": sigma.get("summary", {}),
                "detections": sigma.get("detections", [])[:max_items],
            },
            "yara": {
                "unique_match_count": len(yara_groups),
                "matches": list(yara_groups.values())[:max_items],
            },
            "attack": attack,
            "threat_intel": intel,
            "investigation": {
                "summary": investigation.get("summary", {}),
                "findings": investigation.get("findings", [])[:max_items],
            },
            "graph": {
                "node_count": graph.get("node_count", 0),
                "edge_count": graph.get("edge_count", 0),
                "summary": graph.get("summary", {}),
            },
            "methodology_notes": [
                "Evidence integrity is verified against registered SHA-256 values before report generation.",
                "Sigma, YARA and ATT&CK outputs are investigative indicators and not standalone proof of compromise.",
                "Threat-intelligence inventory is local-only unless an external provider is explicitly configured.",
                "The report reflects only artifacts ingested into this Sentinel case at generation time.",
            ],
        }

    @staticmethod
    def _md_value(value: Any) -> str:
        if value is None:
            return "-"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=True)
        return str(value).replace("\n", " ")

    def _markdown(self, report: dict[str, Any]) -> str:
        meta = report["report"]
        brief = report["executive_summary"]
        lines = [
            f"# Sentinel Forensic Investigation Report - {meta['case_id']}",
            "",
            f"**Case title:** {self._md_value(meta.get('title'))}",
            f"**Generated:** {self._md_value(meta.get('generated_at'))}",
            f"**Status:** {self._md_value(meta.get('case_status'))}",
            "",
            "## Executive Summary",
            "",
            f"**Assessment:** {self._md_value(brief.get('headline'))}",
            f"**Confidence:** {self._md_value(brief.get('confidence'))}",
            "",
            "### Observations",
        ]
        for item in brief.get("observations", []):
            lines.append(f"- **{self._md_value(item.get('title'))}** - {self._md_value(item.get('basis'))}")
        lines += ["", "### Collection Gaps"]
        for item in brief.get("collection_gaps", []):
            lines.append(f"- {self._md_value(item)}")
        lines += ["", "### Recommended Actions"]
        for item in brief.get("recommended_actions", []):
            lines.append(f"- {self._md_value(item)}")

        lines += ["", "## Evidence Integrity", ""]
        integrity = report.get("evidence_integrity", {})
        lines.append(f"- All registered hashes match: **{integrity.get('all_match')}**")
        lines.append(f"- Chain of custody valid: **{integrity.get('chain_of_custody_valid')}**")

        lines += ["", "## Evidence Inventory", "", "| ID | File | Size | SHA-256 |", "|---|---|---:|---|"]
        for item in report.get("evidence_inventory", []):
            lines.append(
                f"| {self._md_value(item.get('evidence_id'))} | {self._md_value(item.get('filename'))} | "
                f"{self._md_value(item.get('size_bytes'))} | `{self._md_value(item.get('sha256'))}` |"
            )

        lines += ["", "## Sigma Detections", ""]
        detections = report.get("sigma", {}).get("detections", [])
        if not detections:
            lines.append("No Sigma detections were reported.")
        for item in detections:
            lines.append(
                f"- **{self._md_value(item.get('title'))}** ({self._md_value(item.get('level'))}) - "
                f"rule `{self._md_value(item.get('rule_id'))}`, evidence {self._md_value(item.get('evidence_id'))}"
            )

        lines += ["", "## YARA Matches", ""]
        matches = report.get("yara", {}).get("matches", [])
        if not matches:
            lines.append("No YARA matches were reported.")
        for item in matches:
            lines.append(
                f"- **{self._md_value(item.get('rule'))}** - evidence {self._md_value(item.get('evidence_id'))}, "
                f"matches: {self._md_value(item.get('match_count'))}"
            )

        lines += ["", "## ATT&CK Candidates", ""]
        candidates = report.get("attack", {}).get("candidates", [])
        if not candidates:
            lines.append("No ATT&CK candidates were reported.")
        for item in candidates:
            lines.append(
                f"- **{self._md_value(item.get('technique_id'))} {self._md_value(item.get('technique_name'))}** - "
                f"{self._md_value(item.get('confidence'))} confidence"
            )

        graph = report.get("graph", {})
        lines += [
            "",
            "## Evidence Graph",
            "",
            f"- Nodes: {graph.get('node_count', 0)}",
            f"- Edges: {graph.get('edge_count', 0)}",
            "",
            "## Methodology Notes",
        ]
        for note in report.get("methodology_notes", []):
            lines.append(f"- {note}")
        lines.append("")
        return "\n".join(lines)

    def _html(self, report: dict[str, Any]) -> str:
        md = self._markdown(report)
        blocks: list[str] = []
        in_table = False
        for raw in md.splitlines():
            line = raw.rstrip()
            if line.startswith("# "):
                blocks.append(f"<h1>{html.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                blocks.append(f"<h2>{html.escape(line[3:])}</h2>")
            elif line.startswith("### "):
                blocks.append(f"<h3>{html.escape(line[4:])}</h3>")
            elif line.startswith("- "):
                blocks.append(f"<p class='bullet'>- {html.escape(line[2:])}</p>")
            elif line.startswith("|"):
                if "---" in line:
                    continue
                cells = [html.escape(cell.strip().strip("`")) for cell in line.strip("|").split("|")]
                tag = "th" if not in_table else "td"
                blocks.append("<tr>" + "".join(f"<{tag}>{cell}</{tag}>" for cell in cells) + "</tr>")
                in_table = True
            elif line:
                blocks.append(f"<p>{html.escape(line.replace('**', '').replace('`', ''))}</p>")
        body = "\n".join(blocks)
        return f"""<!doctype html>
<html><head><meta charset='utf-8'><title>Sentinel Forensic Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;max-width:1040px;margin:40px auto;padding:0 28px;color:#1f2937;line-height:1.5}}
h1{{border-bottom:3px solid #111827;padding-bottom:12px}}h2{{margin-top:30px;border-bottom:1px solid #d1d5db;padding-bottom:6px}}
.bullet{{margin:5px 0 5px 18px}}table{{border-collapse:collapse;width:100%;font-size:13px;word-break:break-word}}th,td{{border:1px solid #d1d5db;padding:7px;text-align:left}}th{{background:#f3f4f6}}
</style></head><body>{body}</body></html>"""

    def _pdf(self, report: dict[str, Any], destination: Path) -> None:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import LongTable, Paragraph, SimpleDocTemplate, Spacer, TableStyle
        except ImportError as exc:
            raise RuntimeError("PDF export requires reportlab; install requirements.txt") from exc

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(
            str(destination), pagesize=A4,
            rightMargin=16 * mm, leftMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
            title=f"Sentinel Forensic Report {report['report']['case_id']}",
        )
        story: list[Any] = []
        meta = report["report"]
        brief = report["executive_summary"]
        story.append(Paragraph(f"Sentinel Forensic Investigation Report - {html.escape(str(meta['case_id']))}", styles["Title"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"Case: {html.escape(str(meta.get('title') or '-'))}", styles["Normal"]))
        story.append(Paragraph(f"Generated: {html.escape(str(meta.get('generated_at')))}", styles["Normal"]))
        story.append(Spacer(1, 10))
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Paragraph(f"Assessment: {html.escape(str(brief.get('headline')))}", styles["Normal"]))
        story.append(Paragraph(f"Confidence: {html.escape(str(brief.get('confidence')))}", styles["Normal"]))
        for item in brief.get("observations", []):
            text = f"- {item.get('title')}: {item.get('basis')}"
            story.append(Paragraph(html.escape(str(text)), styles["BodyText"]))

        story.append(Paragraph("Evidence Integrity", styles["Heading2"]))
        integ = report.get("evidence_integrity", {})
        story.append(Paragraph(f"All registered hashes match: {integ.get('all_match')}", styles["Normal"]))
        story.append(Paragraph(f"Chain of custody valid: {integ.get('chain_of_custody_valid')}", styles["Normal"]))

        story.append(Paragraph("Evidence Inventory", styles["Heading2"]))
        rows = [["ID", "File", "Size", "SHA-256"]]
        for item in report.get("evidence_inventory", []):
            rows.append([
                str(item.get("evidence_id") or "-"),
                str(item.get("filename") or "-"),
                str(item.get("size_bytes") or "-"),
                str(item.get("sha256") or "-"),
            ])
        table = LongTable(rows, colWidths=[18 * mm, 42 * mm, 22 * mm, 92 * mm], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 6.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 3),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(table)

        for heading, items, formatter in (
            ("Sigma Detections", report.get("sigma", {}).get("detections", []), lambda x: f"{x.get('title')} [{x.get('level')}] - {x.get('rule_id')}"),
            ("YARA Matches", report.get("yara", {}).get("matches", []), lambda x: f"{x.get('rule')} - evidence {x.get('evidence_id')}, matches {x.get('match_count')}"),
            ("ATT&CK Candidates", report.get("attack", {}).get("candidates", []), lambda x: f"{x.get('technique_id')} {x.get('technique_name')} - {x.get('confidence')} confidence"),
        ):
            story.append(Paragraph(heading, styles["Heading2"]))
            if not items:
                story.append(Paragraph("None reported.", styles["Normal"]))
            for item in items:
                story.append(Paragraph(html.escape(str(formatter(item))), styles["BodyText"]))

        story.append(Paragraph("Recommended Actions", styles["Heading2"]))
        for item in brief.get("recommended_actions", []):
            story.append(Paragraph(html.escape(f"- {item}"), styles["BodyText"]))
        story.append(Paragraph("Methodology Notes", styles["Heading2"]))
        for item in report.get("methodology_notes", []):
            story.append(Paragraph(html.escape(f"- {item}"), styles["BodyText"]))
        doc.build(story)

    def export(
        self,
        *,
        output_format: str = "all",
        report_name: str | None = None,
        max_items: int = 50,
    ) -> dict[str, Any]:
        fmt = output_format.lower().strip()
        if fmt == "md":
            fmt = "markdown"
        if fmt not in self.FORMATS:
            raise ValueError(f"Unsupported report format: {output_format}")

        report = self.build_report(max_items=max_items)
        reports_dir = self.case_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        default_name = f"{report['report']['case_id']}-investigation-report"
        stem = self._slug(report_name or default_name)
        formats = ["json", "markdown", "html", "pdf"] if fmt == "all" else [fmt]
        outputs: list[dict[str, Any]] = []

        for item in formats:
            suffix = {"json": ".json", "markdown": ".md", "html": ".html", "pdf": ".pdf"}[item]
            path = reports_dir / f"{stem}{suffix}"
            if item == "json":
                path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
            elif item == "markdown":
                path.write_text(self._markdown(report), encoding="utf-8")
            elif item == "html":
                path.write_text(self._html(report), encoding="utf-8")
            else:
                self._pdf(report, path)
            outputs.append({
                "format": item,
                "path": str(path.resolve()),
                "size_bytes": path.stat().st_size,
                "sha256": self._sha256(path),
            })

        manifest = reports_dir / f"{stem}.manifest.json"
        manifest_payload = {
            "case_id": report["report"]["case_id"],
            "generated_at": report["report"]["generated_at"],
            "outputs": outputs,
        }
        manifest.write_text(json.dumps(manifest_payload, indent=2), encoding="utf-8")
        return {
            "case_id": report["report"]["case_id"],
            "report_name": stem,
            "outputs": outputs,
            "manifest": {
                "path": str(manifest.resolve()),
                "sha256": self._sha256(manifest),
            },
            "evidence_integrity": report.get("evidence_integrity"),
        }
