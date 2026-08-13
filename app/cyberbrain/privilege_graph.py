from __future__ import annotations

import json
import sqlite3
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Principal:
    principal_id: str
    principal_type: str
    name: str
    provider: str
    attributes: dict[str, Any]


@dataclass(slots=True)
class PrivilegeEdge:
    source_id: str
    relation: str
    target_id: str
    risk: float = 0.0
    attributes: dict[str, Any] | None = None


class PrivilegeGraphStore:
    VERSION = "X6.0"

    def __init__(self, path: str | Path = "data/privilege_graph.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS principals(principal_id TEXT PRIMARY KEY, principal_type TEXT, name TEXT, provider TEXT, attributes TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS edges(source_id TEXT, relation TEXT, target_id TEXT, risk REAL, attributes TEXT, UNIQUE(source_id,relation,target_id))")

    def ingest(self, principals: list[Principal], edges: list[PrivilegeEdge]) -> dict[str, int]:
        with sqlite3.connect(self.path) as db:
            for p in principals:
                db.execute("INSERT OR REPLACE INTO principals VALUES(?,?,?,?,?)", (p.principal_id, p.principal_type, p.name, p.provider, json.dumps(p.attributes, sort_keys=True)))
            for edge in edges:
                risk = max(0.0, min(1.0, float(edge.risk)))
                db.execute("INSERT OR REPLACE INTO edges VALUES(?,?,?,?,?)", (edge.source_id, edge.relation, edge.target_id, risk, json.dumps(edge.attributes or {}, sort_keys=True)))
        return {"principals": len(principals), "edges": len(edges)}

    def principals(self, *, provider: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT principal_id,principal_type,name,provider,attributes FROM principals"
        params: tuple[Any, ...] = ()
        if provider:
            sql += " WHERE provider=?"; params = (provider,)
        with sqlite3.connect(self.path) as db:
            rows = db.execute(sql, params).fetchall()
        return [{"principal_id": r[0], "principal_type": r[1], "name": r[2], "provider": r[3], "attributes": json.loads(r[4] or "{}")} for r in rows]

    def edges(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT source_id,relation,target_id,risk,attributes FROM edges").fetchall()
        return [{"source_id": r[0], "relation": r[1], "target_id": r[2], "risk": r[3], "attributes": json.loads(r[4] or "{}")} for r in rows]

    def shortest_path(self, source_id: str, target_id: str, *, max_depth: int = 8) -> dict[str, Any]:
        edges = self.edges()
        adjacency: dict[str, list[dict[str, Any]]] = {}
        for edge in edges:
            adjacency.setdefault(edge["source_id"], []).append(edge)
        queue = deque([(source_id, [source_id], [], 0.0)])
        seen = {source_id}
        while queue:
            current, path, path_edges, risk = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue
            for edge in adjacency.get(current, []):
                nxt = edge["target_id"]
                next_risk = max(risk, float(edge.get("risk") or 0.0))
                if nxt == target_id:
                    return {"found": True, "path": path + [nxt], "edges": path_edges + [edge], "max_edge_risk": round(next_risk, 3)}
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, path + [nxt], path_edges + [edge], next_risk))
        return {"found": False, "path": [], "edges": [], "max_edge_risk": 0.0}

    def risky_edges(self, *, minimum_risk: float = 0.6, limit: int = 100) -> list[dict[str, Any]]:
        rows = [edge for edge in self.edges() if float(edge.get("risk") or 0.0) >= minimum_risk]
        rows.sort(key=lambda x: float(x.get("risk") or 0.0), reverse=True)
        return rows[:limit]

    def stats(self) -> dict[str, Any]:
        principals = self.principals(); edges = self.edges()
        providers: dict[str, int] = {}
        for p in principals:
            providers[p["provider"]] = providers.get(p["provider"], 0) + 1
        return {"version": self.VERSION, "principal_count": len(principals), "edge_count": len(edges), "providers": providers, "high_risk_edges": len([e for e in edges if float(e.get("risk") or 0) >= 0.6])}
