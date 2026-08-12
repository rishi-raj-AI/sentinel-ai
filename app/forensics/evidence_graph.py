from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.forensics.sigma_engine import SigmaEngine
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
    """Build a deterministic entity graph from normalized forensic events."""

    _PROC_RE = re.compile(r"process:\s*([^\s].*?)(?=\s+Duration:|\s+Conn_Time:|\s+bytes\s+in/out:|$)", re.I)
    _IFACE_RE = re.compile(r"interface:\s*([A-Za-z0-9_.-]+)", re.I)
    _PORT_PAIR_RE = re.compile(r":(\d{1,5})<->[^:>]+:(\d{1,5})")
    _IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.store = TimelineStore(case_dir)

    @staticmethod
    def _node_id(node_type: str, value: str) -> str:
        return f"{node_type}:{value}"

    @staticmethod
    def _process_name(event: dict[str, Any]) -> str | None:
        details = event.get("details") or {}
        for key in ("ImageFileName", "Name", "Process", "process", "Executable"):
            value = details.get(key)
            if value:
                return str(value)
        command_line = details.get("CommandLine")
        if command_line:
            return str(command_line).split()[0]
        summary = str(event.get("summary") or "")
        if summary and event.get("event_type") == "process":
            return summary
        return None

    @staticmethod
    def _pid(details: dict[str, Any]) -> str | None:
        for key in ("PID", "Pid", "pid", "process_id", "ProcessId"):
            value = details.get(key)
            if value not in (None, "", "N/A"):
                return str(value)
        return None

    @staticmethod
    def _ppid(details: dict[str, Any]) -> str | None:
        for key in ("PPID", "PPid", "ppid", "ParentPid", "InheritedFromUniqueProcessId"):
            value = details.get(key)
            if value not in (None, "", "N/A"):
                return str(value)
        return None

    @staticmethod
    def _default_sigma_rules() -> Path:
        return Path(__file__).resolve().parents[2] / "rules" / "sigma"

    def build(self, *, max_nodes: int = 1000, max_edges: int = 2000) -> dict[str, Any]:
        events = self.store.read()
        nodes: dict[str, GraphNode] = {}
        edges: list[GraphEdge] = []
        seen_edges: set[tuple[str, str, str, str]] = set()

        def add_node(node_type: str, value: str, **attributes: Any) -> str:
            value = str(value).strip()
            node_id = self._node_id(node_type, value)
            if node_id not in nodes and len(nodes) < max_nodes:
                nodes[node_id] = GraphNode(node_id, node_type, value, attributes)
            elif node_id in nodes:
                nodes[node_id].attributes.update({k: v for k, v in attributes.items() if v not in (None, "")})
            return node_id

        def add_edge(source: str, target: str, relation: str, **attributes: Any) -> None:
            if source not in nodes or target not in nodes or len(edges) >= max_edges:
                return
            stamp = str(attributes.get("timestamp") or "")
            key = (source, target, relation, stamp)
            if key in seen_edges:
                return
            seen_edges.add(key)
            edges.append(GraphEdge(source, target, relation, attributes))

        case_json = self.case_dir / "case.json"
        if case_json.is_file():
            try:
                case_record = json.loads(case_json.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                case_record = {}
            for item in case_record.get("evidence", []):
                evidence_id = item.get("evidence_id")
                if not evidence_id:
                    continue
                evidence_node = add_node(
                    "evidence",
                    str(evidence_id),
                    filename=item.get("filename"),
                    sha256=item.get("sha256"),
                    size_bytes=item.get("size_bytes"),
                    registered_at=item.get("registered_at"),
                    original_path=item.get("original_path"),
                    stored_path=item.get("stored_path"),
                )
                stored_path = item.get("stored_path")
                if stored_path:
                    file_node = add_node("file", str(stored_path), preserved=True)
                    add_edge(evidence_node, file_node, "stored_as", registered_at=item.get("registered_at"))

        process_by_pid: dict[str, str] = {}

        for event in events:
            event_type = str(event.get("event_type") or "unknown").lower()
            source = str(event.get("source") or "unknown")
            details = event.get("details") or {}
            summary = str(event.get("summary") or "")
            evidence_id = event.get("evidence_id")
            timestamp = event.get("timestamp")

            event_node = add_node(
                "event",
                f"{timestamp}|{source}|{summary}",
                event_type=event_type,
                source=source,
                timestamp=timestamp,
                evidence_id=evidence_id,
            )

            evidence_node: str | None = None
            if evidence_id:
                evidence_node = add_node("evidence", str(evidence_id))
                add_edge(evidence_node, event_node, "contains", timestamp=timestamp)

            if event_type == "yara_match" or source == "yara":
                rule = details.get("rule")
                if rule:
                    yara_node = add_node(
                        "yara_rule",
                        str(rule),
                        tags=details.get("tags") or [],
                        metadata=details.get("metadata") or {},
                        rule_path=details.get("rule_path"),
                    )
                    add_edge(event_node, yara_node, "matched_rule", timestamp=timestamp)
                    if evidence_node:
                        add_edge(evidence_node, yara_node, "matched", timestamp=timestamp)
                evidence_path = details.get("evidence_path")
                if evidence_path:
                    file_node = add_node("file", str(evidence_path))
                    add_edge(event_node, file_node, "scanned_file", timestamp=timestamp)
                    if evidence_node:
                        add_edge(evidence_node, file_node, "stored_as", timestamp=timestamp)

            process_name = self._process_name(event)
            pid = self._pid(details)
            ppid = self._ppid(details)
            process_node: str | None = None
            if process_name:
                process_label = f"{process_name} [{pid}]" if pid else process_name
                process_node = add_node("process", process_label, name=process_name, pid=pid)
                add_edge(event_node, process_node, "describes", timestamp=timestamp)
                if pid:
                    process_by_pid[pid] = process_node
                if ppid:
                    parent = process_by_pid.get(ppid)
                    if parent:
                        add_edge(parent, process_node, "spawned", timestamp=timestamp)

            if source == "macos_unified_log":
                mac_proc = details.get("process")
                if mac_proc:
                    proc_label = f"{mac_proc} [{details.get('process_id')}]" if details.get("process_id") else str(mac_proc)
                    process_node = add_node("process", proc_label, name=mac_proc, pid=details.get("process_id"))
                    add_edge(event_node, process_node, "emitted", timestamp=timestamp)

                message = str(details.get("message") or summary)
                interface_match = self._IFACE_RE.search(message)
                if interface_match:
                    interface_node = add_node("interface", interface_match.group(1))
                    add_edge(event_node, interface_node, "used_interface", timestamp=timestamp)
                    if process_node:
                        add_edge(process_node, interface_node, "used_interface", timestamp=timestamp)

                proc_match = self._PROC_RE.search(message)
                if proc_match:
                    embedded_proc = proc_match.group(1).strip()
                    embedded_node = add_node("process", embedded_proc, name=embedded_proc)
                    add_edge(event_node, embedded_node, "mentions_process", timestamp=timestamp)
                    process_node = process_node or embedded_node

                port_match = self._PORT_PAIR_RE.search(message)
                if port_match:
                    src_port, dst_port = port_match.groups()
                    src_port_node = add_node("port", src_port)
                    dst_port_node = add_node("port", dst_port)
                    add_edge(event_node, src_port_node, "source_port", timestamp=timestamp)
                    add_edge(event_node, dst_port_node, "destination_port", timestamp=timestamp)
                    if process_node:
                        add_edge(process_node, dst_port_node, "connected_via_port", timestamp=timestamp)

                for ip_value in self._IPV4_RE.findall(message):
                    ip_node = add_node("ip", ip_value)
                    add_edge(event_node, ip_node, "mentions_ip", timestamp=timestamp)

            if event_type == "network":
                src = details.get("src") or details.get("LocalAddr") or details.get("LocalAddress")
                dst = details.get("dst") or details.get("ForeignAddr") or details.get("ForeignAddress")
                src_port = details.get("tcp_srcport") or details.get("udp_srcport") or details.get("LocalPort")
                dst_port = details.get("tcp_dstport") or details.get("udp_dstport") or details.get("ForeignPort")

                src_node = add_node("ip", str(src)) if src else None
                dst_node = add_node("ip", str(dst)) if dst else None
                if src_node:
                    add_edge(event_node, src_node, "source_ip", timestamp=timestamp)
                if dst_node:
                    add_edge(event_node, dst_node, "destination_ip", timestamp=timestamp)
                if src_node and dst_node:
                    add_edge(src_node, dst_node, "connected_to", timestamp=timestamp, src_port=src_port, dst_port=dst_port)
                if process_node and dst_node:
                    add_edge(process_node, dst_node, "connected_to", timestamp=timestamp, dst_port=dst_port)

                for port_value, relation in ((src_port, "source_port"), (dst_port, "destination_port")):
                    if port_value:
                        port_node = add_node("port", str(port_value))
                        add_edge(event_node, port_node, relation, timestamp=timestamp)
                        if process_node and relation == "destination_port":
                            add_edge(process_node, port_node, "connected_via_port", timestamp=timestamp)

                for field, relation in (("dns_query", "queried"), ("http_host", "contacted"), ("tls_sni", "tls_to")):
                    value = details.get(field)
                    if value:
                        domain_node = add_node("domain", str(value))
                        add_edge(event_node, domain_node, relation, timestamp=timestamp)
                        if process_node:
                            add_edge(process_node, domain_node, relation, timestamp=timestamp)

            path = details.get("path") or details.get("Path") or details.get("file") or details.get("FileName")
            if path:
                node_type = "module" if event_type == "module" else "file"
                file_node = add_node(node_type, str(path))
                add_edge(event_node, file_node, "describes", timestamp=timestamp)
                if process_node:
                    relation = "loaded" if node_type == "module" else "touched"
                    add_edge(process_node, file_node, relation, timestamp=timestamp)

        # Sigma is evaluated read-only and overlaid onto the graph. Detections are
        # not written back into the timeline, avoiding duplicate detection events
        # while still making the rule/evidence/event relationship queryable.
        rules_path = self._default_sigma_rules()
        if rules_path.is_dir():
            sigma = SigmaEngine(self.case_dir).analyze(str(rules_path), max_detections=250)
            for detection in sigma.get("detections", []):
                rule_id = str(detection.get("rule_id") or "unnamed-rule")
                timestamp = detection.get("event_timestamp")
                sigma_rule = add_node(
                    "sigma_rule",
                    rule_id,
                    title=detection.get("title"),
                    level=detection.get("level"),
                    tags=detection.get("tags") or [],
                )
                detection_id = f"{rule_id}|{timestamp}|{detection.get('evidence_id') or ''}"
                detection_node = add_node(
                    "detection",
                    detection_id,
                    engine="sigma",
                    rule_id=rule_id,
                    title=detection.get("title"),
                    level=detection.get("level"),
                    timestamp=timestamp,
                    evidence_id=detection.get("evidence_id"),
                )
                add_edge(detection_node, sigma_rule, "triggered_by", timestamp=timestamp)
                evidence_id = detection.get("evidence_id")
                if evidence_id:
                    evidence_node = add_node("evidence", str(evidence_id))
                    add_edge(evidence_node, detection_node, "produced_detection", timestamp=timestamp)
                event = detection.get("event") or {}
                event_id = self._node_id(
                    "event",
                    f"{event.get('timestamp')}|{event.get('source')}|{event.get('summary')}",
                )
                if event_id in nodes:
                    add_edge(detection_node, event_id, "detected", timestamp=timestamp)

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
