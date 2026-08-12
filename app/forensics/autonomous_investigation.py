from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.case_copilot_v3 import CaseCopilot
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.timeline import TimelineStore


class AutonomousInvestigationAgent:
    """Read-only analysis orchestrator with persisted investigation notebook.

    The agent never acquires evidence or executes external forensic commands. It
    operates on evidence already registered and normalized in a Sentinel case,
    records exactly which analytical steps were run, produces competing
    hypotheses, and persists the resulting notebook under the case directory.
    """

    def __init__(self, case_dir: str | Path, sigma_rules: str = "rules/sigma") -> None:
        self.case_dir = Path(case_dir)
        self.sigma_rules = sigma_rules
        self.timeline = TimelineStore(case_dir)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _slug(text: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
        return value[:48] or "investigation"

    @staticmethod
    def _confidence_label(score: int) -> str:
        if score >= 75:
            return "high"
        if score >= 45:
            return "medium"
        return "low"

    def plan(self, objective: str) -> list[dict[str, Any]]:
        lower = objective.lower()
        steps = [
            {"id": "coverage", "title": "Assess evidence coverage", "engine": "case_reasoning"},
            {"id": "detections", "title": "Review Sigma and YARA detections", "engine": "sigma+timeline"},
            {"id": "network", "title": "Review network behavior", "engine": "network_intelligence"},
            {"id": "attack", "title": "Review ATT&CK candidates", "engine": "attack_mapping"},
            {"id": "graph", "title": "Review evidence relationships", "engine": "evidence_graph"},
        ]
        if any(term in lower for term in ("malware", "infection", "compromise", "incident", "suspicious")):
            steps.append({"id": "hypotheses", "title": "Compare compromise and benign hypotheses", "engine": "hypothesis_manager"})
        else:
            steps.append({"id": "hypotheses", "title": "Generate competing explanations", "engine": "hypothesis_manager"})
        steps.append({"id": "synthesis", "title": "Produce grounded investigator synthesis", "engine": "case_copilot"})
        return steps

    @staticmethod
    def _yara_groups(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for event in events:
            if event.get("source") != "yara" and event.get("event_type") != "yara_match":
                continue
            details = event.get("details") or {}
            key = (str(event.get("evidence_id") or ""), str(details.get("rule") or "unknown"))
            row = groups.setdefault(key, {
                "evidence_id": event.get("evidence_id"),
                "rule": details.get("rule"),
                "match_count": 0,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
            })
            row["match_count"] += 1
            stamp = event.get("timestamp")
            if stamp and (not row["first_seen"] or stamp < row["first_seen"]):
                row["first_seen"] = stamp
            if stamp and (not row["last_seen"] or stamp > row["last_seen"]):
                row["last_seen"] = stamp
        return list(groups.values())

    def _hypotheses(
        self,
        brief: dict[str, Any],
        sigma: dict[str, Any],
        yara: list[dict[str, Any]],
        network: dict[str, Any],
        attack: dict[str, Any],
    ) -> list[dict[str, Any]]:
        sigma_count = int(sigma.get("detection_count", 0))
        yara_count = len(yara)
        unusual = len(network.get("findings", {}).get("unusual_destination_ports", []))
        attack_count = int(attack.get("candidate_count", 0))
        memory_present = int(brief.get("coverage", {}).get("volatility_events", 0)) > 0
        evtx_present = int(brief.get("coverage", {}).get("evtx_events", 0)) > 0

        compromise = min(92, 18 + sigma_count * 18 + yara_count * 12 + unusual * 10 + attack_count * 10 + (8 if memory_present else 0) + (5 if evtx_present else 0))
        benign = max(8, min(85, 62 - sigma_count * 10 - yara_count * 8 - unusual * 7 - attack_count * 7 + (8 if not memory_present else 0)))
        false_positive = max(5, min(80, 54 - attack_count * 8 - (8 if memory_present else 0) + (12 if yara and all("test" in str(row.get("rule") or "").lower() for row in yara) else 0)))

        support = [item.get("title") for item in brief.get("observations", [])[:6] if item.get("title")]
        gaps = brief.get("collection_gaps", [])
        return [
            {
                "id": "H1",
                "statement": "The observed signals are consistent with potentially malicious activity requiring investigation.",
                "confidence_percent": compromise,
                "confidence": self._confidence_label(compromise),
                "support": support,
                "limitations": gaps + ["Detections and unusual ports are indicators, not proof of malicious intent."],
            },
            {
                "id": "H2",
                "statement": "The observed activity may have a benign or administrative explanation.",
                "confidence_percent": benign,
                "confidence": self._confidence_label(benign),
                "support": ["No autonomous compromise verdict is established by the current evidence."],
                "limitations": ["Benign explanation remains weaker when multiple independent detections converge."],
            },
            {
                "id": "H3",
                "statement": "Some or all current detections may be validation artifacts or false positives.",
                "confidence_percent": false_positive,
                "confidence": self._confidence_label(false_positive),
                "support": [f"Unique YARA matches: {yara_count}", f"Sigma detections: {sigma_count}"],
                "limitations": ["A false-positive hypothesis must be tested against original evidence and surrounding events."],
            },
        ]

    def run(self, objective: str, *, max_items: int = 25, persist: bool = True) -> dict[str, Any]:
        objective = objective.strip()
        if not objective:
            raise ValueError("Investigation objective is required")

        started = self._now()
        plan = self.plan(objective)
        notebook: list[dict[str, Any]] = []

        brief = CaseReasoningEngine(self.case_dir, sigma_rules=self.sigma_rules).build(max_items=max_items)
        notebook.append({"step": "coverage", "timestamp": self._now(), "status": "completed", "result": brief.get("coverage", {})})

        sigma = SigmaEngine(self.case_dir).analyze(self.sigma_rules, max_detections=max_items)
        events = self.timeline.read()
        yara = self._yara_groups(events)
        notebook.append({
            "step": "detections", "timestamp": self._now(), "status": "completed",
            "result": {"sigma_detections": sigma.get("detection_count", 0), "yara_unique_matches": len(yara)},
        })

        network = NetworkIntelligenceEngine(self.case_dir).analyze(max_flows=max_items)
        notebook.append({
            "step": "network", "timestamp": self._now(), "status": "completed",
            "result": {"flow_count": network.get("flow_count", 0), "findings": network.get("findings", {})},
        })

        attack = AttackMappingEngine(self.case_dir).analyze(max_candidates=max_items)
        notebook.append({
            "step": "attack", "timestamp": self._now(), "status": "completed",
            "result": {"candidate_count": attack.get("candidate_count", 0), "candidates": attack.get("candidates", [])[:max_items]},
        })

        graph = EvidenceGraphEngine(self.case_dir).build(max_nodes=3000, max_edges=6000)
        notebook.append({
            "step": "graph", "timestamp": self._now(), "status": "completed",
            "result": {"node_count": graph.get("node_count", 0), "edge_count": graph.get("edge_count", 0), "nodes_by_type": graph.get("nodes_by_type", {}), "edges_by_relation": graph.get("edges_by_relation", {})},
        })

        hypotheses = self._hypotheses(brief, sigma, yara, network, attack)
        notebook.append({"step": "hypotheses", "timestamp": self._now(), "status": "completed", "result": hypotheses})

        copilot = CaseCopilot(self.case_dir, sigma_rules=self.sigma_rules)
        synthesis_question = (
            f"Investigation objective: {objective}. Summarize the strongest supported findings, competing explanations, "
            "important limitations, and next investigative actions. Do not declare compromise unless the evidence supports it."
        )
        synthesis = copilot.answer(synthesis_question, max_sources=min(16, max_items))
        notebook.append({
            "step": "synthesis", "timestamp": self._now(), "status": "completed",
            "result": {"mode": synthesis.get("mode"), "model": synthesis.get("model"), "source_count": synthesis.get("source_count"), "provider_error": synthesis.get("provider_error")},
        })

        ranked = sorted(hypotheses, key=lambda row: int(row.get("confidence_percent", 0)), reverse=True)
        leading = ranked[0] if ranked else None
        overall = int(leading.get("confidence_percent", 0)) if leading else 0
        run_seed = f"{started}|{objective}|{len(events)}".encode("utf-8")
        run_id = f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{hashlib.sha256(run_seed).hexdigest()[:8]}"

        result = {
            "run_id": run_id,
            "objective": objective,
            "started_at": started,
            "completed_at": self._now(),
            "mode": "read-only-analysis",
            "plan": plan,
            "notebook": notebook,
            "leading_hypothesis": leading,
            "hypotheses": ranked,
            "overall_confidence_percent": overall,
            "overall_confidence": self._confidence_label(overall),
            "observations": brief.get("observations", [])[:max_items],
            "collection_gaps": brief.get("collection_gaps", []),
            "recommended_actions": brief.get("recommended_actions", []),
            "attack_candidates": attack.get("candidates", [])[:max_items],
            "sigma_detections": sigma.get("detections", [])[:max_items],
            "yara_matches": yara[:max_items],
            "network_findings": network.get("findings", {}),
            "graph_summary": {"node_count": graph.get("node_count", 0), "edge_count": graph.get("edge_count", 0)},
            "synthesis": synthesis,
            "interpretation": "This autonomous run performs analytical orchestration only. It does not acquire evidence, alter endpoints, or establish a compromise verdict by itself.",
        }

        if persist:
            paths = self._persist(result)
            result["artifacts"] = paths
        return result

    def _persist(self, result: dict[str, Any]) -> dict[str, Any]:
        directory = self.case_dir / "investigations"
        directory.mkdir(parents=True, exist_ok=True)
        run_id = str(result["run_id"])
        json_path = directory / f"{run_id}.json"
        md_path = directory / f"{run_id}.md"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

        lines = [
            f"# Sentinel Autonomous Investigation — {run_id}", "",
            f"**Objective:** {result['objective']}",
            f"**Overall confidence:** {result['overall_confidence_percent']}% ({result['overall_confidence']})", "",
            "## Leading hypothesis", "",
            str((result.get("leading_hypothesis") or {}).get("statement") or "No hypothesis generated."), "",
            "## Competing hypotheses", "",
        ]
        for row in result.get("hypotheses", []):
            lines.append(f"- **{row['id']} — {row['confidence_percent']}%:** {row['statement']}")
        lines.extend(["", "## Recommended actions", ""])
        lines.extend(f"- {item}" for item in result.get("recommended_actions", []))
        lines.extend(["", "## Collection gaps", ""])
        lines.extend(f"- {item}" for item in result.get("collection_gaps", []))
        lines.extend(["", "## Copilot synthesis", "", str((result.get("synthesis") or {}).get("answer") or ""), "", "## Notebook", ""])
        for entry in result.get("notebook", []):
            lines.append(f"- `{entry['timestamp']}` **{entry['step']}** — {entry['status']}")
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        def item(path: Path) -> dict[str, Any]:
            data = path.read_bytes()
            return {"path": str(path), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

        return {"json": item(json_path), "markdown": item(md_path)}

    def list_runs(self) -> list[dict[str, Any]]:
        directory = self.case_dir / "investigations"
        if not directory.exists():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(directory.glob("INV-*.json"), reverse=True):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rows.append({
                "run_id": data.get("run_id"),
                "objective": data.get("objective"),
                "completed_at": data.get("completed_at"),
                "overall_confidence_percent": data.get("overall_confidence_percent"),
                "overall_confidence": data.get("overall_confidence"),
                "leading_hypothesis": (data.get("leading_hypothesis") or {}).get("statement"),
            })
        return rows

    def load_run(self, run_id: str) -> dict[str, Any]:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "", run_id)
        if safe != run_id:
            raise ValueError("Invalid investigation run ID")
        path = self.case_dir / "investigations" / f"{run_id}.json"
        if not path.is_file():
            raise FileNotFoundError(run_id)
        return json.loads(path.read_text(encoding="utf-8"))
