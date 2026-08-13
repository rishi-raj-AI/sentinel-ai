from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TwinNode:
    node_id: str
    node_type: str
    name: str
    criticality: float = 0.5
    attributes: dict[str, Any] | None = None


@dataclass(slots=True)
class TwinEdge:
    source_id: str
    relation: str
    target_id: str
    exposure: float = 0.5
    controls: list[str] | None = None
    attributes: dict[str, Any] | None = None


class DigitalTwinStore:
    """Persistent organization digital twin with non-executing attack-path/control simulation."""

    VERSION = "X8.0"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,type TEXT,name TEXT,criticality REAL,attributes TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS edges(source TEXT,relation TEXT,target TEXT,exposure REAL,controls TEXT,attributes TEXT,UNIQUE(source,relation,target))")

    def ingest(self, nodes: list[TwinNode], edges: list[TwinEdge]) -> dict[str, int]:
        with sqlite3.connect(self.path) as db:
            for n in nodes:
                db.execute("INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?)", (n.node_id,n.node_type,n.name,max(0,min(1,n.criticality)),json.dumps(n.attributes or {},sort_keys=True)))
            for e in edges:
                db.execute("INSERT OR REPLACE INTO edges VALUES(?,?,?,?,?,?)", (e.source_id,e.relation,e.target_id,max(0,min(1,e.exposure)),json.dumps(e.controls or []),json.dumps(e.attributes or {},sort_keys=True)))
        return {"nodes_ingested": len(nodes), "edges_ingested": len(edges)}

    def _graph(self):
        with sqlite3.connect(self.path) as db:
            nodes = {r[0]: {"id":r[0],"type":r[1],"name":r[2],"criticality":r[3],"attributes":json.loads(r[4] or "{}")} for r in db.execute("SELECT * FROM nodes")}
            edges = [{"source":r[0],"relation":r[1],"target":r[2],"exposure":r[3],"controls":json.loads(r[4] or "[]"),"attributes":json.loads(r[5] or "{}")} for r in db.execute("SELECT * FROM edges")]
        return nodes, edges

    def simulate_paths(self, source_id: str, *, target_type: str | None = None, max_depth: int = 6, limit: int = 50) -> dict[str, Any]:
        nodes, edges = self._graph()
        if source_id not in nodes:
            return {"found": False, "paths": []}
        adj: dict[str, list[dict[str, Any]]] = {}
        for e in edges:
            adj.setdefault(e["source"], []).append(e)
        queue = deque([(source_id,[source_id],[],1.0)])
        paths = []
        while queue and len(paths) < limit:
            current, path, path_edges, score = queue.popleft()
            if len(path)-1 >= max_depth:
                continue
            for edge in adj.get(current, []):
                nxt = edge["target"]
                if nxt in path:
                    continue
                controls = edge.get("controls") or []
                control_factor = max(0.25, 1.0 - min(0.75, len(controls)*0.18))
                next_score = score * float(edge.get("exposure",0.5)) * control_factor
                new_path = path + [nxt]
                new_edges = path_edges + [edge]
                target = nodes.get(nxt, {})
                if target and (target_type is None or target.get("type") == target_type):
                    risk = min(1.0, next_score * (0.5 + float(target.get("criticality",0.5))))
                    paths.append({"path":new_path,"edges":new_edges,"target":target,"simulated_risk":round(risk,3),"control_count":sum(len(x.get("controls") or []) for x in new_edges)})
                queue.append((nxt,new_path,new_edges,next_score))
        paths.sort(key=lambda x: x["simulated_risk"], reverse=True)
        return {"found": bool(paths), "source_id": source_id, "target_type": target_type, "paths": paths}

    def coverage(self) -> dict[str, Any]:
        nodes, edges = self._graph()
        controlled = sum(1 for e in edges if e.get("controls"))
        return {"version":self.VERSION,"node_count":len(nodes),"edge_count":len(edges),"controlled_edges":controlled,"uncontrolled_edges":len(edges)-controlled,"coverage_ratio":round(controlled/len(edges),3) if edges else 0.0,"policy":{"simulation_only":True,"no_production_actions":True}}
