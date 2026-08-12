from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any

from app.forensics.evidence_graph import EvidenceGraphEngine


class EvidenceGraphQueryEngine:
    """Query and traverse the deterministic evidence graph for a case."""

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)

    def _graph(self, max_nodes: int = 5000, max_edges: int = 10000) -> dict[str, Any]:
        return EvidenceGraphEngine(self.case_dir).build(max_nodes=max_nodes, max_edges=max_edges)

    @staticmethod
    def _resolve_node(nodes: list[dict[str, Any]], query: str) -> dict[str, Any] | None:
        q = query.strip().lower()
        exact = [node for node in nodes if str(node.get("id", "")).lower() == q]
        if exact:
            return exact[0]
        label_matches = [node for node in nodes if str(node.get("label", "")).lower() == q]
        if label_matches:
            return label_matches[0]
        partial = [node for node in nodes if q in str(node.get("label", "")).lower() or q in str(node.get("id", "")).lower()]
        if len(partial) == 1:
            return partial[0]
        return None

    def neighbors(self, query: str, *, depth: int = 1, max_results: int = 100) -> dict[str, Any]:
        if depth < 1 or depth > 5:
            raise ValueError("depth must be between 1 and 5")
        graph = self._graph()
        nodes = graph["nodes"]
        edges = graph["edges"]
        start = self._resolve_node(nodes, query)
        if not start:
            matches = [node for node in nodes if query.lower() in str(node.get("label", "")).lower()][:20]
            return {"resolved": False, "query": query, "matches": matches}

        adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for edge in edges:
            adjacency.setdefault(edge["source"], []).append((edge["target"], edge))
            adjacency.setdefault(edge["target"], []).append((edge["source"], edge))

        node_by_id = {node["id"]: node for node in nodes}
        queue = deque([(start["id"], 0)])
        visited = {start["id"]}
        found_nodes: list[dict[str, Any]] = []
        found_edges: list[dict[str, Any]] = []

        while queue and len(found_nodes) < max_results:
            current, level = queue.popleft()
            if level >= depth:
                continue
            for neighbor_id, edge in adjacency.get(current, []):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    node = node_by_id.get(neighbor_id)
                    if node:
                        found_nodes.append(node)
                    queue.append((neighbor_id, level + 1))
                if edge not in found_edges:
                    found_edges.append(edge)

        return {
            "resolved": True,
            "query": query,
            "start_node": start,
            "depth": depth,
            "connected_node_count": len(found_nodes),
            "connected_edge_count": len(found_edges),
            "nodes": found_nodes[:max_results],
            "edges": found_edges[: max_results * 3],
        }

    def trace(self, source_query: str, target_query: str, *, max_hops: int = 6) -> dict[str, Any]:
        if max_hops < 1 or max_hops > 10:
            raise ValueError("max_hops must be between 1 and 10")
        graph = self._graph()
        nodes = graph["nodes"]
        edges = graph["edges"]
        source = self._resolve_node(nodes, source_query)
        target = self._resolve_node(nodes, target_query)
        if not source or not target:
            return {
                "resolved": False,
                "source_resolved": source,
                "target_resolved": target,
                "source_query": source_query,
                "target_query": target_query,
            }

        adjacency: dict[str, list[tuple[str, dict[str, Any]]]] = {}
        for edge in edges:
            adjacency.setdefault(edge["source"], []).append((edge["target"], edge))
            adjacency.setdefault(edge["target"], []).append((edge["source"], edge))

        queue = deque([(source["id"], [])])
        visited = {source["id"]}
        found_path: list[dict[str, Any]] | None = None

        while queue:
            current, path = queue.popleft()
            if len(path) >= max_hops:
                continue
            for neighbor, edge in adjacency.get(current, []):
                step = {"from": current, "to": neighbor, "relation": edge["relation"], "attributes": edge.get("attributes", {})}
                new_path = path + [step]
                if neighbor == target["id"]:
                    found_path = new_path
                    queue.clear()
                    break
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, new_path))

        return {
            "resolved": True,
            "source": source,
            "target": target,
            "path_found": found_path is not None,
            "hop_count": len(found_path) if found_path else None,
            "path": found_path or [],
        }
