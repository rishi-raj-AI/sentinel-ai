from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class KnowledgeEntity:
    entity_id: str
    entity_type: str
    name: str
    attributes: dict[str, Any]
    source: str
    confidence: float = 1.0
    observed_at: str | None = None


@dataclass(slots=True)
class KnowledgeRelation:
    source_id: str
    relation: str
    target_id: str
    attributes: dict[str, Any]
    source: str
    confidence: float = 1.0


class KnowledgeStore:
    VERSION = "X2.0"

    def __init__(self, path: str | Path = "data/cyber_knowledge.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS entities(entity_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, name TEXT NOT NULL, attributes TEXT NOT NULL, source TEXT NOT NULL, confidence REAL NOT NULL, observed_at TEXT, updated_at TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS relations(id INTEGER PRIMARY KEY AUTOINCREMENT, source_id TEXT NOT NULL, relation TEXT NOT NULL, target_id TEXT NOT NULL, attributes TEXT NOT NULL, source TEXT NOT NULL, confidence REAL NOT NULL, updated_at TEXT NOT NULL, UNIQUE(source_id, relation, target_id, source))")
            db.execute("CREATE INDEX IF NOT EXISTS idx_entities_type ON entities(entity_type)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_rel_source ON relations(source_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_rel_target ON relations(target_id)")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def upsert_entity(self, entity: KnowledgeEntity) -> dict[str, Any]:
        payload = asdict(entity)
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO entities(entity_id,entity_type,name,attributes,source,confidence,observed_at,updated_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(entity_id) DO UPDATE SET entity_type=excluded.entity_type,name=excluded.name,attributes=excluded.attributes,source=excluded.source,confidence=excluded.confidence,observed_at=excluded.observed_at,updated_at=excluded.updated_at",
                (entity.entity_id, entity.entity_type, entity.name, json.dumps(entity.attributes, sort_keys=True), entity.source, max(0.0, min(1.0, entity.confidence)), entity.observed_at, self._now()),
            )
        return payload

    def upsert_relation(self, relation: KnowledgeRelation) -> dict[str, Any]:
        payload = asdict(relation)
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT INTO relations(source_id,relation,target_id,attributes,source,confidence,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id,relation,target_id,source) DO UPDATE SET attributes=excluded.attributes,confidence=excluded.confidence,updated_at=excluded.updated_at",
                (relation.source_id, relation.relation, relation.target_id, json.dumps(relation.attributes, sort_keys=True), relation.source, max(0.0, min(1.0, relation.confidence)), self._now()),
            )
        return payload

    def ingest(self, *, entities: Iterable[KnowledgeEntity] = (), relations: Iterable[KnowledgeRelation] = ()) -> dict[str, int]:
        entity_count = 0
        relation_count = 0
        for entity in entities:
            self.upsert_entity(entity)
            entity_count += 1
        for relation in relations:
            self.upsert_relation(relation)
            relation_count += 1
        return {"entities": entity_count, "relations": relation_count}

    def search(self, query: str, *, entity_type: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        needle = f"%{query.casefold()}%"
        sql = "SELECT entity_id,entity_type,name,attributes,source,confidence,observed_at FROM entities WHERE (lower(entity_id) LIKE ? OR lower(name) LIKE ? OR lower(attributes) LIKE ?)"
        params: list[Any] = [needle, needle, needle]
        if entity_type:
            sql += " AND entity_type=?"
            params.append(entity_type)
        sql += " ORDER BY confidence DESC, name ASC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with sqlite3.connect(self.path) as db:
            rows = db.execute(sql, params).fetchall()
        return [{"entity_id": r[0], "entity_type": r[1], "name": r[2], "attributes": json.loads(r[3]), "source": r[4], "confidence": r[5], "observed_at": r[6]} for r in rows]

    def neighbors(self, entity_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT source_id,relation,target_id,attributes,source,confidence FROM relations WHERE source_id=? OR target_id=? ORDER BY confidence DESC LIMIT ?", (entity_id, entity_id, max(1, min(limit, 1000)))).fetchall()
        return [{"source_id": r[0], "relation": r[1], "target_id": r[2], "attributes": json.loads(r[3]), "source": r[4], "confidence": r[5]} for r in rows]

    def stats(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            entity_count = db.execute("SELECT COUNT(*) FROM entities").fetchone()[0]
            relation_count = db.execute("SELECT COUNT(*) FROM relations").fetchone()[0]
            types = dict(db.execute("SELECT entity_type,COUNT(*) FROM entities GROUP BY entity_type").fetchall())
        return {"version": self.VERSION, "entity_count": entity_count, "relation_count": relation_count, "entity_types": types}
