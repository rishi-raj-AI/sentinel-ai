from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.forensics.timeline import TimelineEvent, TimelineStore
from app.enterprise.core import KnowledgeGraphService
from app.forensics.network_intelligence import NetworkIntelligenceEngine


def run(event_count: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "CASE-BENCH"
        case_dir.mkdir(parents=True)
        (case_dir / "case.json").write_text('{"case_id":"CASE-BENCH","evidence":[]}', encoding="utf-8")
        store = TimelineStore(case_dir)
        started = time.perf_counter()
        for i in range(event_count):
            store.append(TimelineEvent(
                timestamp=f"2026-08-13T10:{(i // 60) % 60:02d}:{i % 60:02d}+00:00",
                source="benchmark",
                event_type="network",
                summary=f"10.0.0.{i % 250 + 1} -> 198.51.100.{i % 250 + 1}",
                details={"src": f"10.0.0.{i % 250 + 1}", "dst": f"198.51.100.{i % 250 + 1}", "udp_srcport": str(40000 + i % 1000), "udp_dstport": "443", "protocols": "ip:udp"},
                evidence_id="E-BENCH",
            ))
        ingest_seconds = time.perf_counter() - started

        started = time.perf_counter()
        network = NetworkIntelligenceEngine(case_dir).analyze(max_flows=event_count)
        network_seconds = time.perf_counter() - started

        started = time.perf_counter()
        graph = KnowledgeGraphService(case_dir).snapshot(max_nodes=max(5000, event_count * 4), max_edges=max(10000, event_count * 8))
        graph_seconds = time.perf_counter() - started

        return {
            "event_count": event_count,
            "ingest_seconds": round(ingest_seconds, 4),
            "network_seconds": round(network_seconds, 4),
            "graph_seconds": round(graph_seconds, 4),
            "flows": network.get("flow_count", 0),
            "graph_nodes": graph.get("node_count", 0),
            "graph_edges": graph.get("edge_count", 0),
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=10000)
    args = parser.parse_args()
    print(json.dumps(run(args.events), indent=2))
