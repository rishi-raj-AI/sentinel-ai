from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.enterprise.core import InvestigationReasoningService, KnowledgeGraphService
from app.enterprise.workspace import RBAC
from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.case_copilot_v6 import CaseCopilot
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.timeline import TimelineStore


@dataclass(slots=True)
class AgentFinding:
    agent: str
    specialty: str
    summary: str
    confidence: float
    supporting: list[str]
    contradicting: list[str]
    gaps: list[str]
    recommendations: list[str]
    metrics: dict[str, Any]


class SpecialistAgent:
    name = "specialist"
    specialty = "general"

    def __init__(self, case_dir: str | Path, sigma_rules: str = "rules/sigma") -> None:
        self.case_dir = Path(case_dir)
        self.sigma_rules = sigma_rules

    @staticmethod
    def _clamp(value: float) -> float:
        return round(max(0.0, min(1.0, value)), 3)

    def run(self, objective: str) -> AgentFinding:  # pragma: no cover - abstract contract
        raise NotImplementedError


class NetworkAnalystAgent(SpecialistAgent):
    name = "network-analyst"
    specialty = "network"

    def run(self, objective: str) -> AgentFinding:
        data = NetworkIntelligenceEngine(self.case_dir).analyze(max_flows=100)
        flows = data.get("flows", []) or []
        findings = data.get("findings", {}) or {}
        unusual = findings.get("unusual_destination_ports", []) or []
        support = [f"FLOW:{i}" for i in range(1, min(len(flows), 25) + 1)]
        confidence = self._clamp(0.35 + min(0.35, len(unusual) * 0.10) + min(0.20, len(flows) * 0.02))
        gaps = [] if flows else ["No normalized network flows are available."]
        summary = f"Reviewed {len(flows)} network flows; {len(unusual)} unusual-destination-port finding(s) were reported."
        return AgentFinding(self.name, self.specialty, summary, confidence, support, [], gaps,
                            ["Correlate unusual flows with endpoint process/user telemetry."],
                            {"flow_count": len(flows), "unusual_destination_port_count": len(unusual)})


class DetectionAnalystAgent(SpecialistAgent):
    name = "detection-analyst"
    specialty = "sigma+yara"

    def run(self, objective: str) -> AgentFinding:
        sigma = SigmaEngine(self.case_dir).analyze(self.sigma_rules, max_detections=100)
        detections = sigma.get("detections", []) or []
        events = TimelineStore(self.case_dir).read()
        yara = [e for e in events if e.get("source") == "yara" or e.get("event_type") == "yara_match"]
        support: list[str] = []
        for i, row in enumerate(detections, start=1):
            rid = str(row.get("rule_id") or row.get("id") or row.get("title") or "rule")
            support.append(f"SIGMA:{rid}:{i}")
        for event in yara[:25]:
            rule = str((event.get("details") or {}).get("rule") or "unknown")
            evidence = str(event.get("evidence_id") or "unknown")
            support.append(f"YARA:{evidence}:{rule}")
        test_like = sum("test" in str((e.get("details") or {}).get("rule") or "").casefold() for e in yara)
        contradictions = ["One or more YARA matches use test-like rule names."] if test_like else []
        confidence = self._clamp(0.30 + min(0.35, len(detections) * 0.12) + min(0.25, len(yara) * 0.06) - (0.08 if test_like else 0))
        gaps = [] if (detections or yara) else ["No Sigma or YARA detections are available."]
        return AgentFinding(self.name, self.specialty,
                            f"Reviewed {len(detections)} Sigma detection(s) and {len(yara)} YARA event(s).",
                            confidence, list(dict.fromkeys(support)), contradictions, gaps,
                            ["Validate detections against surrounding events and originating evidence."],
                            {"sigma_count": len(detections), "yara_event_count": len(yara), "test_like_yara_count": test_like})


class MemoryAnalystAgent(SpecialistAgent):
    name = "memory-analyst"
    specialty = "memory"

    def run(self, objective: str) -> AgentFinding:
        brief = CaseReasoningEngine(self.case_dir, sigma_rules=self.sigma_rules).build(max_items=50)
        coverage = brief.get("coverage", {}) or {}
        count = int(coverage.get("volatility_events", 0) or 0)
        gaps = [] if count else ["No successfully parsed memory-forensics artifacts are present."]
        confidence = self._clamp(0.25 + min(0.55, count * 0.04)) if count else 0.20
        support = [f"MEMORY:COVERAGE:{count}"] if count else []
        recs = ["Acquire and analyze an authorized memory image if memory evidence is required."] if not count else ["Correlate memory process/network artifacts with graph entities."]
        return AgentFinding(self.name, self.specialty,
                            f"Memory coverage contains {count} normalized Volatility event(s).",
                            confidence, support, [], gaps, recs, {"volatility_events": count})


class ThreatHunterAgent(SpecialistAgent):
    name = "threat-hunter"
    specialty = "attack+graph"

    def run(self, objective: str) -> AgentFinding:
        attack = AttackMappingEngine(self.case_dir).analyze(max_candidates=100)
        candidates = attack.get("candidates", []) or []
        graph = KnowledgeGraphService(self.case_dir).snapshot(max_nodes=5000, max_edges=10000)
        support: list[str] = []
        for row in candidates[:25]:
            technique = row.get("technique_id") or row.get("technique") or row.get("id")
            if technique:
                support.append(f"ATTACK:{technique}")
        confidence = self._clamp(0.30 + min(0.35, len(candidates) * 0.07) + min(0.20, graph.get("edge_count", 0) * 0.002))
        gaps = [] if graph.get("node_count", 0) else ["Evidence graph is empty."]
        return AgentFinding(self.name, self.specialty,
                            f"Mapped {len(candidates)} ATT&CK candidate(s) across a graph with {graph.get('node_count', 0)} nodes and {graph.get('edge_count', 0)} edges.",
                            confidence, support, [], gaps,
                            ["Traverse graph paths connecting detections, evidence, processes and network entities."],
                            {"attack_candidate_count": len(candidates), "graph_nodes": graph.get("node_count", 0), "graph_edges": graph.get("edge_count", 0)})


class CounterEvidenceAgent(SpecialistAgent):
    name = "counter-evidence-agent"
    specialty = "contradiction"

    def run(self, objective: str) -> AgentFinding:
        service = InvestigationReasoningService(self.case_dir)
        keywords = ["test", "validation", "update", "system", "benign", "normal"]
        rows = service.counter_evidence(keywords, limit=40)
        contradicting = [str(row.get("id") or row.get("label")) for row in rows[:20]]
        confidence = self._clamp(0.25 + min(0.55, len(rows) * 0.04))
        return AgentFinding(self.name, self.specialty,
                            f"Searched the knowledge graph for alternative/contradicting context and found {len(rows)} candidate node(s).",
                            confidence, [], contradicting, [],
                            ["Review counter-evidence before escalating any compromise hypothesis."],
                            {"counter_evidence_candidate_count": len(rows), "keywords": keywords})


class SOCSupervisor:
    """Read-only multi-agent SOC orchestrator with auditable reconciliation."""

    VERSION = "5.0"
    AGENT_TYPES = (NetworkAnalystAgent, DetectionAnalystAgent, MemoryAnalystAgent, ThreatHunterAgent, CounterEvidenceAgent)

    def __init__(self, case_dir: str | Path, sigma_rules: str = "rules/sigma") -> None:
        self.case_dir = Path(case_dir)
        self.sigma_rules = sigma_rules

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def run(self, objective: str, *, role: str = "analyst", persist: bool = True) -> dict[str, Any]:
        RBAC.require(role, "job.run")
        objective = objective.strip()
        if not objective:
            raise ValueError("SOC objective is required")
        started = self._now()
        findings: list[AgentFinding] = []
        transcript: list[dict[str, Any]] = []
        for agent_type in self.AGENT_TYPES:
            agent = agent_type(self.case_dir, sigma_rules=self.sigma_rules)
            finding = agent.run(objective)
            findings.append(finding)
            transcript.append({"timestamp": self._now(), "agent": finding.agent, "event": "analysis.completed", "finding": asdict(finding)})

        supporting = list(dict.fromkeys(item for f in findings for item in f.supporting))
        contradicting = list(dict.fromkeys(item for f in findings for item in f.contradicting))
        gaps = list(dict.fromkeys(item for f in findings for item in f.gaps))
        agent_mean = round(sum(f.confidence for f in findings) / max(1, len(findings)), 3)
        quality = max(0.45, min(0.95, agent_mean))
        scored = InvestigationReasoningService(self.case_dir).score_hypothesis(
            "The observed case signals warrant escalation for potential malicious activity.",
            supporting=supporting, contradicting=contradicting, gaps=gaps, source_quality=quality,
        )

        specialist_digest = "\n".join(f"- {f.agent}: {f.summary}" for f in findings)
        copilot = CaseCopilot(self.case_dir, sigma_rules=self.sigma_rules)
        synthesis = copilot.answer(
            f"SOC objective: {objective}. Reconcile these specialist findings without inventing evidence:\n{specialist_digest}\n"
            "State the strongest supported observations, disagreements/counter-evidence, collection gaps, and next authorized investigative actions.",
            max_sources=16,
        )
        transcript.append({"timestamp": self._now(), "agent": "soc-supervisor", "event": "synthesis.completed",
                           "mode": synthesis.get("mode"), "provider_error": synthesis.get("provider_error")})

        seed = f"{started}|{self.case_dir.name}|{objective}".encode()
        run_id = f"SOC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{hashlib.sha256(seed).hexdigest()[:8]}"
        result = {
            "version": self.VERSION,
            "run_id": run_id,
            "case_id": self.case_dir.name,
            "objective": objective,
            "started_at": started,
            "completed_at": self._now(),
            "mode": "read-only-multi-agent-analysis",
            "agents": [asdict(f) for f in findings],
            "agent_count": len(findings),
            "agent_mean_confidence": agent_mean,
            "supervisor_hypothesis": asdict(scored),
            "supporting_evidence": supporting,
            "counter_evidence": contradicting,
            "collection_gaps": gaps,
            "recommendations": list(dict.fromkeys(item for f in findings for item in f.recommendations)),
            "synthesis": synthesis,
            "transcript": transcript,
            "guardrails": {
                "read_only": True,
                "evidence_acquisition": False,
                "endpoint_remediation": False,
                "compromise_verdict_requires_evidence": True,
                "specialist_disagreement_preserved": True,
            },
        }
        if persist:
            result["artifacts"] = self._persist(result)
        return result

    def _persist(self, result: dict[str, Any]) -> dict[str, Any]:
        directory = self.case_dir / "soc_runs"
        directory.mkdir(parents=True, exist_ok=True)
        run_id = result["run_id"]
        json_path = directory / f"{run_id}.json"
        md_path = directory / f"{run_id}.md"
        json_path.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        lines = [f"# Sentinel SOC Run — {run_id}", "", f"**Objective:** {result['objective']}", "",
                 f"**Supervisor confidence:** {result['supervisor_hypothesis']['confidence']:.1%}", "", "## Specialist findings", ""]
        lines.extend(f"- **{row['agent']} ({row['confidence']:.1%})** — {row['summary']}" for row in result["agents"])
        lines += ["", "## Counter-evidence", ""] + [f"- {x}" for x in result["counter_evidence"]]
        lines += ["", "## Collection gaps", ""] + [f"- {x}" for x in result["collection_gaps"]]
        lines += ["", "## Recommendations", ""] + [f"- {x}" for x in result["recommendations"]]
        lines += ["", "## Grounded supervisor synthesis", "", str(result.get("synthesis", {}).get("answer") or "")]
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        def meta(path: Path) -> dict[str, Any]:
            data = path.read_bytes()
            return {"path": str(path), "size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        return {"json": meta(json_path), "markdown": meta(md_path)}

    def list_runs(self) -> list[dict[str, Any]]:
        directory = self.case_dir / "soc_runs"
        rows: list[dict[str, Any]] = []
        if not directory.is_dir():
            return rows
        for path in sorted(directory.glob("SOC-*.json"), reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rows.append({"run_id": payload.get("run_id"), "objective": payload.get("objective"),
                         "started_at": payload.get("started_at"),
                         "confidence": (payload.get("supervisor_hypothesis") or {}).get("confidence")})
        return rows

    def load_run(self, run_id: str) -> dict[str, Any]:
        path = self.case_dir / "soc_runs" / f"{run_id}.json"
        if not path.is_file():
            raise FileNotFoundError(run_id)
        return json.loads(path.read_text(encoding="utf-8"))
