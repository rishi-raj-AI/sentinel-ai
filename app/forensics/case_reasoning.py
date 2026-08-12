from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.investigation import InvestigationEngine
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.timeline import TimelineStore


class CaseReasoningEngine:
    """Produce an evidence-grounded investigation brief from Sentinel subsystems.

    This engine is deterministic. It summarizes observed evidence and explicitly
    separates observations, detections, hypotheses, gaps and recommended actions.
    It does not treat a detection or ATT&CK mapping as proof of compromise.
    """

    def __init__(self, case_dir: str | Path, sigma_rules: str = "rules/sigma") -> None:
        self.case_dir = Path(case_dir)
        self.timeline = TimelineStore(case_dir)
        self.sigma_rules = sigma_rules

    @staticmethod
    def _confidence(score: int) -> str:
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"

    def build(self, *, max_items: int = 20) -> dict[str, Any]:
        events = self.timeline.read()
        heuristic = InvestigationEngine(self.case_dir).analyze(window_seconds=120, max_findings=max_items)
        network = NetworkIntelligenceEngine(self.case_dir).analyze(max_flows=max_items)
        sigma = SigmaEngine(self.case_dir).analyze(self.sigma_rules, max_detections=max_items)
        attack = AttackMappingEngine(self.case_dir).analyze(max_candidates=max_items)
        graph = EvidenceGraphEngine(self.case_dir).build(max_nodes=3000, max_edges=6000)

        yara_events = [e for e in events if e.get("source") == "yara" or e.get("event_type") == "yara_match"]
        evtx_events = [e for e in events if e.get("source") == "evtx"]
        volatility_events = [e for e in events if e.get("source") == "volatility"]
        pcap_events = [e for e in events if e.get("source") == "tshark"]

        observations: list[dict[str, Any]] = []
        for detection in sigma.get("detections", [])[:max_items]:
            observations.append({
                "kind": "sigma_detection",
                "severity": detection.get("level", "medium"),
                "title": detection.get("title"),
                "evidence_id": detection.get("evidence_id"),
                "timestamp": detection.get("event_timestamp"),
                "basis": f"Sigma rule {detection.get('rule_id')} matched selections {detection.get('matched_selections', [])}",
            })
        for event in yara_events[:max_items]:
            observations.append({
                "kind": "yara_match",
                "severity": "medium",
                "title": event.get("summary"),
                "evidence_id": event.get("evidence_id"),
                "timestamp": event.get("timestamp"),
                "basis": f"YARA rule {(event.get('details') or {}).get('rule')} matched preserved evidence",
            })
        for flow in network.get("findings", {}).get("unusual_destination_ports", [])[:max_items]:
            observations.append({
                "kind": "network_anomaly",
                "severity": "medium",
                "title": "Unusual destination port",
                "evidence_id": (flow.get("evidence_ids") or [None])[0],
                "timestamp": flow.get("first_seen"),
                "basis": f"{flow.get('protocol')} flow {flow.get('src')}:{flow.get('src_port')} -> {flow.get('dst')}:{flow.get('dst_port')}",
            })

        evidence_sources = Counter(str(e.get("source") or "unknown") for e in events)
        score = 0
        score += min(4, sigma.get("detection_count", 0) * 2)
        score += min(2, len(yara_events))
        score += 1 if network.get("findings", {}).get("unusual_destination_ports") else 0
        score += 1 if attack.get("candidate_count", 0) else 0
        confidence = self._confidence(score)

        hypotheses: list[dict[str, Any]] = []
        if sigma.get("detection_count") or yara_events:
            hypotheses.append({
                "statement": "The case contains rule-based indicators that warrant investigator review.",
                "confidence": confidence,
                "support": [item["title"] for item in observations[:5]],
                "limitation": "Rule matches indicate patterns of interest; they do not independently establish malicious intent.",
            })
        elif network.get("findings", {}).get("unusual_destination_ports"):
            hypotheses.append({
                "statement": "The case contains unusual network behavior without corroborating execution or malware evidence.",
                "confidence": "medium",
                "support": ["Unusual destination-port flow"],
                "limitation": "Network-port rarity alone is not evidence of command-and-control.",
            })
        else:
            hypotheses.append({
                "statement": "No strong multi-source compromise pattern is established by the currently ingested evidence.",
                "confidence": "medium",
                "support": ["No high-confidence rule/behavior convergence"],
                "limitation": "Absence of detections is not proof of absence; collection coverage may be incomplete.",
            })

        gaps: list[str] = []
        recommendations: list[str] = []
        if not volatility_events:
            gaps.append("No successfully parsed memory-forensics artifacts are present.")
            recommendations.append("Acquire an authorized memory image and run process, command-line, network and module Volatility plugins.")
        if not evtx_events:
            gaps.append("No normalized Windows EVTX events are present.")
            recommendations.append("Collect Security, Sysmon, PowerShell Operational, Defender and Task Scheduler EVTX logs where applicable.")
        if not pcap_events:
            gaps.append("No packet-capture events are present.")
            recommendations.append("Collect a scoped PCAP when network behavior is relevant to the incident.")
        if network.get("findings", {}).get("unusual_destination_ports"):
            recommendations.append("Identify the process/user responsible for each unusual network flow and correlate it with endpoint telemetry.")
        if sigma.get("detection_count"):
            recommendations.append("Validate each Sigma detection against surrounding timeline events and the originating evidence before escalation.")
        if yara_events:
            recommendations.append("Review YARA-matched files in context and confirm whether the rule is test-only, generic, or malware-specific.")

        headline = "No high-confidence compromise established"
        if score >= 7:
            headline = "Multiple evidence signals require priority review"
        elif score >= 4:
            headline = "Some evidence signals warrant focused review"
        elif observations:
            headline = "Limited indicators present; corroboration is needed"

        return {
            "headline": headline,
            "confidence": confidence,
            "observations": observations[:max_items],
            "hypotheses": hypotheses,
            "attack_candidates": attack.get("candidates", [])[:max_items],
            "collection_gaps": gaps,
            "recommended_actions": recommendations,
            "coverage": {
                "total_events": len(events),
                "events_by_source": dict(evidence_sources),
                "sigma_detections": sigma.get("detection_count", 0),
                "yara_matches": len(yara_events),
                "evtx_events": len(evtx_events),
                "volatility_events": len(volatility_events),
                "pcap_events": len(pcap_events),
                "graph_nodes": graph.get("node_count", 0),
                "graph_edges": graph.get("edge_count", 0),
            },
            "interpretation": "This brief is evidence-grounded decision support, not an autonomous compromise verdict.",
        }
