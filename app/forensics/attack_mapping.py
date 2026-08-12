from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.investigation import InvestigationEngine
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.timeline import TimelineStore


@dataclass(slots=True)
class AttackCandidate:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str
    reason: str
    evidence: list[dict[str, Any]]


class AttackMappingEngine:
    """Conservative, deterministic ATT&CK candidate mapper.

    ATT&CK is a behavior framework, not a protocol-labeling system. This engine
    only emits candidates when observed artifacts include stronger contextual
    signals; ordinary DNS/HTTP/network traffic is not mapped by itself.
    """

    SCRIPT_MAPPINGS = (
        ("powershell", "T1059.001", "PowerShell", "Execution"),
        ("osascript", "T1059.002", "AppleScript", "Execution"),
        ("applescript", "T1059.002", "AppleScript", "Execution"),
        ("cmd.exe", "T1059.003", "Windows Command Shell", "Execution"),
        ("/bin/sh", "T1059.004", "Unix Shell", "Execution"),
        ("/bin/bash", "T1059.004", "Unix Shell", "Execution"),
        ("/bin/zsh", "T1059.004", "Unix Shell", "Execution"),
        ("python ", "T1059.006", "Python", "Execution"),
        ("python3 ", "T1059.006", "Python", "Execution"),
    )

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.store = TimelineStore(case_dir)

    @staticmethod
    def _event_blob(event: dict[str, Any]) -> str:
        return f"{event.get('summary', '')} {event.get('details', {})}".lower()

    def _script_candidates(self, events: list[dict[str, Any]]) -> list[AttackCandidate]:
        candidates: list[AttackCandidate] = []
        seen: set[tuple[str, str]] = set()
        for event in events:
            blob = self._event_blob(event)
            for marker, technique_id, technique_name, tactic in self.SCRIPT_MAPPINGS:
                if marker not in blob:
                    continue
                key = (technique_id, str(event.get("timestamp")))
                if key in seen:
                    continue
                seen.add(key)
                score = InvestigationEngine.score_event(event)
                candidates.append(
                    AttackCandidate(
                        technique_id=technique_id,
                        technique_name=technique_name,
                        tactic=tactic,
                        confidence="medium" if score >= 8 else "low",
                        reason=f"Observed command/script interpreter indicator '{marker.strip()}' in forensic event",
                        evidence=[event],
                    )
                )
        return candidates

    def _network_candidates(self) -> list[AttackCandidate]:
        network = NetworkIntelligenceEngine(self.case_dir).analyze(max_flows=100)
        candidates: list[AttackCandidate] = []

        # Only suspicious-context DNS is considered a T1071.004 candidate. DNS
        # presence by itself is intentionally insufficient.
        unusual = network.get("findings", {}).get("unusual_destination_ports", [])
        unusual_evidence = {eid for flow in unusual for eid in flow.get("evidence_ids", [])}
        dns_queries = network.get("dns_queries", {})
        if dns_queries and unusual_evidence:
            candidates.append(
                AttackCandidate(
                    technique_id="T1071.004",
                    technique_name="Application Layer Protocol: DNS",
                    tactic="Command and Control",
                    confidence="low",
                    reason=(
                        "DNS activity exists in evidence that also contains an unusual network flow; "
                        "this is a review candidate, not proof of DNS-based command and control"
                    ),
                    evidence=[{"evidence_ids": sorted(unusual_evidence), "dns_queries": dns_queries}],
                )
            )

        http_hosts = network.get("http_hosts", {})
        tls_sni = network.get("tls_sni", {})
        if (http_hosts or tls_sni) and unusual_evidence:
            candidates.append(
                AttackCandidate(
                    technique_id="T1071.001",
                    technique_name="Application Layer Protocol: Web Protocols",
                    tactic="Command and Control",
                    confidence="low",
                    reason=(
                        "HTTP/TLS application-layer activity co-occurs with an unusual network flow; "
                        "manual validation is required before treating it as C2"
                    ),
                    evidence=[{
                        "evidence_ids": sorted(unusual_evidence),
                        "http_hosts": http_hosts,
                        "tls_sni": tls_sni,
                    }],
                )
            )
        return candidates

    @staticmethod
    def _deduplicate(candidates: list[AttackCandidate]) -> list[AttackCandidate]:
        rank = {"low": 1, "medium": 2, "high": 3}
        best: dict[tuple[str, str], AttackCandidate] = {}
        for candidate in candidates:
            key = (candidate.technique_id, candidate.reason)
            previous = best.get(key)
            if previous is None or rank[candidate.confidence] > rank[previous.confidence]:
                best[key] = candidate
        return list(best.values())

    def analyze(self, *, max_candidates: int = 25) -> dict[str, Any]:
        events = self.store.read()
        candidates = self._script_candidates(events)
        candidates.extend(self._network_candidates())
        candidates = self._deduplicate(candidates)[:max_candidates]

        by_tactic: dict[str, int] = {}
        by_technique: dict[str, int] = {}
        for candidate in candidates:
            by_tactic[candidate.tactic] = by_tactic.get(candidate.tactic, 0) + 1
            by_technique[candidate.technique_id] = by_technique.get(candidate.technique_id, 0) + 1

        graph = EvidenceGraphEngine(self.case_dir).build(max_nodes=1500, max_edges=3000)
        return {
            "candidate_count": len(candidates),
            "candidates": [asdict(candidate) for candidate in candidates],
            "summary": {
                "by_tactic": by_tactic,
                "by_technique": by_technique,
                "graph_node_count": graph["node_count"],
                "graph_edge_count": graph["edge_count"],
                "interpretation": "ATT&CK candidates require investigator validation; absence/presence is not a compromise verdict",
            },
        }
