from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineStore


@dataclass(slots=True)
class GraphNode:
    id: str
    type: str
    label: str
    attributes: dict[str, Any]


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    attributes: dict[str, Any]


class EvidenceGraphEngine:
    """Build a deterministic evidence graph from normalized forensic events."""

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.store = TimelineStore(case_dir)

    @staticmethod
    def _node_id(node_type: str, value: str) -> str:
        return f"{node_type}:{value}"

    @staticmethod
    def _process_name(event: dict[str, Any]) -> str | None:
        details = event.get("details") or {}
        for key in ("ImageFileName", "Name", "Process", "process", "Executable", "CommandLine"):
            value = details.get(key)
            if value:
                return str(value)
        summary = str(event.get("summary") or "")
        if summary and event.get("event_type") == "process":
            return summary
        return None

    def build(self, *, max_nodes: int = 1000, max_edges: int = 2000) -> dict[str, Any]:
        events = self.store.read()
        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []

        def add_node(node_type: str, value: str, **attributes: Any) -> str:
            node_id = self._node_id(node_type, value)
            if node_id not in nodes and len(nodes) < max_nodes:
                nodes[node_id] = GraphNode(node_id, node_type, value, attributes)
            return node_id

        def add_edge(source: str, target: str, relation: str, **attributes: Any) -> None:
            if source in nodes and target in nodes and len(edges) < max_edges:
                edges.append(GraphEdge(source, target, relation, attributes))

        last_process_node: str | None = None

        for event in events:
            event_type = str(event.get("event_type") or "unknown").lower()
            details = event.get("details") or {}
            evidence_id = event.get("evidence_id")
            timestamp = event.get("timestamp")

            event_node = add_node(
                "event",
                f"{timestamp}|{event.get('source')}|{event.get('summary')}",
                event_type=event_type,
                source=event.get("source"),
                timestamp=timestamp,
                evidence_id=evidence_id,
            )

            if evidence_id:
                evidence_node = add_node("evidence", str(evidence_id))
                add_edge(evidence_node, event_node, "contains", timestamp=timestamp)

            if event_type == "process":
                process_name = self._process_name(event)
                if process_name:
                    process_node = add_node("process", process_name, timestamp=timestamp)
                    add_edge(event_node, process_node, "describes", timestamp=timestamp)
                    if last_process_node and last_process_node != process_node:
                        add_edge(last_process_node, process_node, "followed_by", timestamp=timestamp)
                    last_process_node = process_node

            if event_type == "network":
                src = details.get("src")
                dst = details.get("dst")
                if src:
                    src_node = add_node("ip", str(src))
                    add_edge(event_node, src_node, "source_ip", timestamp=timestamp)
                if dst:
                    dst_node = add_node("ip", str(dst))
                    add_edge(event_node, dst_node, "destination_ip", timestamp=timestamp)
                if src and dst:
                    src_node = self._node_id("ip", str(src))
                    dst_node = self._node_id("ip", str(dst))
                    add_edge(
                        src_node,
                        dst_node,
                        "connected_to",
                        timestamp=timestamp,
                        src_port=details.get("tcp_srcport") or details.get("udp_srcport"),
                        dst_port=details.get("tcp_dstport") or details.get("udp_dstport"),
                    )
                for field, relation in (("dns_query", "queried"), ("http_host", "contacted"), ("tls_sni", "tls_to")):
                    value = details.get(field)
                    if value:
                        domain_node = add_node("domain", str(value))
                        add_edge(event_node, domain_node, relation, timestamp=timestamp)
                        if last_process_node:
                            add_edge(last_process_node, domain_node, relation, timestamp=timestamp)

            if event_type == "file":
                path = details.get("path") or details.get("Path") or details.get("file")
                if path:
                    file_node = add_node("file", str(path))
                    add_edge(event_node, file_node, "describes", timestamp=timestamp)
                    if last_process_node:
                        add_edge(last_process_node, file_node, "touched", timestamp=timestamp)

        type_counts = Counter(node.type for node in nodes.values())
        relation_counts = Counter(edge.relation for edge in edges)

        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": [asdict(node) for node in nodes.values()],
            "edges": [asdict(edge) for edge in edges],
            "summary": {
                "nodes_by_type": dict(type_counts),
                "edges_by_relation": dict(relation_counts),
                "nodes_truncated": len(nodes) >= max_nodes,
                "edges_truncated": len(edges) >= max_edges,
            },
        }
