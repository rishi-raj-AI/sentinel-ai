from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from app.forensics.evidence_graph import EvidenceGraphEngine


@dataclass(slots=True)
class HypothesisScore:
    hypothesis: str
    confidence: float
    supporting: list[str]
    contradicting: list[str]
    gaps: list[str]
    components: dict[str, float]


class KnowledgeGraphService:
    """Normalized graph facade over Sentinel's deterministic evidence graph."""

    VERSION = "3.0"

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)

    def snapshot(self, *, max_nodes: int = 5000, max_edges: int = 10000) -> dict[str, Any]:
        graph = EvidenceGraphEngine(self.case_dir).build(max_nodes=max_nodes, max_edges=max_edges)
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        return {
            "version": self.VERSION,
            "case_id": self.case_dir.name,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_types": dict(Counter(str(n.get("type") or "unknown") for n in nodes)),
            "relations": dict(Counter(str(e.get("relation") or "unknown") for e in edges)),
        }

    @staticmethod
    def _adjacency(graph: dict[str, Any]) -> dict[str, list[tuple[str, dict[str, Any]]]]:
        adj: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for edge in graph.get("edges", []):
            src, dst = str(edge.get("source")), str(edge.get("target"))
            adj.setdefault(src, []).append((dst, edge))
            adj.setdefault(dst, []).append((src, edge))
        return adj

    def neighbors(self, node_id: str, *, depth: int = 1, limit: int = 200) -> dict[str, Any]:
        graph = self.snapshot()
        node_map = {str(n.get("id")): n for n in graph["nodes"]}
        if node_id not in node_map:
            return {"node_id": node_id, "nodes": [], "edges": [], "found": False}
        adj = self._adjacency(graph)
        seen = {node_id}
        frontier = deque([(node_id, 0)])
        edge_keys: set[tuple[str, str, str]] = set()
        edges: list[dict[str, Any]] = []
        while frontier and len(seen) < limit:
            current, level = frontier.popleft()
            if level >= max(0, depth):
                continue
            for nxt, edge in adj.get(current, []):
                key = (str(edge.get("source")), str(edge.get("target")), str(edge.get("relation")))
                if key not in edge_keys:
                    edge_keys.add(key)
                    edges.append(edge)
                if nxt not in seen:
                    seen.add(nxt)
                    frontier.append((nxt, level + 1))
        return {"node_id": node_id, "found": True, "nodes": [node_map[x] for x in seen if x in node_map], "edges": edges}

    def shortest_path(self, source: str, target: str, *, max_depth: int = 8) -> dict[str, Any]:
        graph = self.snapshot()
        node_ids = {str(n.get("id")) for n in graph["nodes"]}
        if source not in node_ids or target not in node_ids:
            return {"found": False, "path": [], "edges": []}
        adj = self._adjacency(graph)
        queue = deque([(source, [source], [])])
        seen = {source}
        while queue:
            current, path, path_edges = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue
            for nxt, edge in adj.get(current, []):
                if nxt == target:
                    return {"found": True, "path": path + [nxt], "edges": path_edges + [edge]}
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, path + [nxt], path_edges + [edge]))
        return {"found": False, "path": [], "edges": []}

    @classmethod
    def cross_case_correlate(cls, case_dirs: Iterable[str | Path], value: str) -> dict[str, Any]:
        needle = value.casefold()
        matches: list[dict[str, Any]] = []
        for case_dir in case_dirs:
            service = cls(case_dir)
            graph = service.snapshot()
            for node in graph["nodes"]:
                blob = f"{node.get('id')} {node.get('label')} {node.get('attributes')}".casefold()
                if needle in blob:
                    matches.append({"case_id": Path(case_dir).name, "node": node})
        return {"query": value, "matches": matches, "case_count": len({m['case_id'] for m in matches})}


class InvestigationReasoningService:
    """Explainable hypothesis scoring and counter-evidence search over graph facts."""

    HIGH_SIGNAL_TYPES = {
        "yara_rule": 3.0,
        "sigma_rule": 3.0,
        "evidence": 2.6,
        "process": 2.4,
        "file": 2.2,
        "ip": 2.0,
        "domain": 2.0,
        "port": 1.6,
        "event": 0.7,
    }
    GENERIC_TERMS = {"system", "normal", "activity", "event", "service"}

    def __init__(self, case_dir: str | Path) -> None:
        self.graph_service = KnowledgeGraphService(case_dir)

    def counter_evidence(self, keywords: Iterable[str], *, limit: int = 50) -> list[dict[str, Any]]:
        """Return counter-evidence candidates ranked by forensic relevance.

        Exact/high-signal matches on evidence, detections, files, processes and
        network entities outrank broad matches on generic event nodes. Returned
        rows include an auditable relevance score and matched terms.
        """
        graph = self.graph_service.snapshot()
        terms = [str(k).strip().casefold() for k in keywords if str(k).strip()]
        ranked: list[tuple[float, dict[str, Any]]] = []
        for node in graph["nodes"]:
            node_type = str(node.get("type") or "unknown").casefold()
            label = str(node.get("label") or "")
            node_id = str(node.get("id") or "")
            attrs = str(node.get("attributes") or "")
            label_blob = f"{node_id} {label}".casefold()
            full_blob = f"{label_blob} {attrs.casefold()}"
            matched = [term for term in terms if term in full_blob]
            if not matched:
                continue

            type_weight = self.HIGH_SIGNAL_TYPES.get(node_type, 1.0)
            score = type_weight
            exact_label_hits = 0
            attribute_hits = 0
            for term in matched:
                generic_penalty = 0.25 if term in self.GENERIC_TERMS else 1.0
                if term in label_blob:
                    exact_label_hits += 1
                    score += 2.2 * generic_penalty
                elif term in attrs.casefold():
                    attribute_hits += 1
                    score += 1.1 * generic_penalty
                if term in {"test", "validation", "false positive", "benign", "update", "known"}:
                    score += 1.5

            # Generic event-only matches are deliberately suppressed so routine
            # OS logging cannot swamp direct contradictory evidence.
            if node_type == "event" and all(term in self.GENERIC_TERMS for term in matched):
                score *= 0.2

            enriched = dict(node)
            enriched["relevance_score"] = round(score, 3)
            enriched["matched_terms"] = matched
            enriched["relevance_components"] = {
                "node_type_weight": type_weight,
                "label_hits": exact_label_hits,
                "attribute_hits": attribute_hits,
                "generic_event_suppressed": node_type == "event" and all(term in self.GENERIC_TERMS for term in matched),
            }
            ranked.append((score, enriched))

        ranked.sort(key=lambda item: (item[0], str(item[1].get("id") or "")), reverse=True)
        return [row for _, row in ranked[:limit]]

    def score_hypothesis(
        self,
        hypothesis: str,
        *,
        supporting: list[str],
        contradicting: list[str] | None = None,
        gaps: list[str] | None = None,
        source_quality: float = 0.8,
    ) -> HypothesisScore:
        contradicting = contradicting or []
        gaps = gaps or []
        evidence_quantity = min(1.0, len(set(supporting)) / 5.0)
        contradiction_penalty = min(0.6, len(set(contradicting)) * 0.15)
        gap_penalty = min(0.4, len(set(gaps)) * 0.08)
        quality = max(0.0, min(1.0, source_quality))
        raw = 0.25 + (0.35 * evidence_quantity) + (0.40 * quality) - contradiction_penalty - gap_penalty
        confidence = round(max(0.0, min(1.0, raw)), 3)
        return HypothesisScore(
            hypothesis=hypothesis,
            confidence=confidence,
            supporting=supporting,
            contradicting=contradicting,
            gaps=gaps,
            components={
                "base": 0.25,
                "evidence_quantity": round(0.35 * evidence_quantity, 3),
                "source_quality": round(0.40 * quality, 3),
                "contradiction_penalty": round(contradiction_penalty, 3),
                "gap_penalty": round(gap_penalty, 3),
            },
        )
