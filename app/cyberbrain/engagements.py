from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


@dataclass(slots=True)
class ScopeRule:
    value: str
    kind: str = "domain"
    include: bool = True


class EngagementStore:
    VERSION = "X3.0"

    def __init__(self, path: str | Path = "data/engagements.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS engagements(engagement_id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL, status TEXT NOT NULL, rules TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT NOT NULL, asset_type TEXT NOT NULL, value TEXT NOT NULL, metadata TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(engagement_id, asset_type, value))")
            db.execute("CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, engagement_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, asset_value TEXT, cwe TEXT, cvss REAL, evidence TEXT NOT NULL, description TEXT NOT NULL, remediation TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_engagement(self, engagement_id: str, name: str, owner: str, rules: list[ScopeRule], *, expires_at: str | None = None) -> dict[str, Any]:
        if not engagement_id.strip() or not rules:
            raise ValueError("engagement_id and at least one scope rule are required")
        serialized = json.dumps([asdict(r) for r in rules], sort_keys=True)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO engagements(engagement_id,name,owner,status,rules,created_at,expires_at) VALUES(?,?,?,?,?,?,?)", (engagement_id, name, owner, "active", serialized, self._now(), expires_at))
        return self.get_engagement(engagement_id)

    def get_engagement(self, engagement_id: str) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT engagement_id,name,owner,status,rules,created_at,expires_at FROM engagements WHERE engagement_id=?", (engagement_id,)).fetchone()
        if not row:
            raise KeyError(engagement_id)
        return {"engagement_id": row[0], "name": row[1], "owner": row[2], "status": row[3], "rules": json.loads(row[4]), "created_at": row[5], "expires_at": row[6]}

    @staticmethod
    def _host(value: str) -> str:
        parsed = urlparse(value if "://" in value else f"//{value}")
        return (parsed.hostname or value).strip().lower().rstrip(".")

    @classmethod
    def _matches(cls, value: str, rule: ScopeRule) -> bool:
        candidate = cls._host(value)
        if rule.kind == "domain":
            target = rule.value.lower().lstrip("*.").rstrip(".")
            return candidate == target or candidate.endswith("." + target)
        if rule.kind == "exact":
            return value.casefold() == rule.value.casefold()
        if rule.kind == "cidr":
            try:
                return ipaddress.ip_address(candidate) in ipaddress.ip_network(rule.value, strict=False)
            except ValueError:
                return False
        return False

    def in_scope(self, engagement_id: str, value: str) -> bool:
        engagement = self.get_engagement(engagement_id)
        rules = [ScopeRule(**r) for r in engagement["rules"]]
        if any(self._matches(value, r) for r in rules if not r.include):
            return False
        return any(self._matches(value, r) for r in rules if r.include)

    def add_asset(self, engagement_id: str, asset_type: str, value: str, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.in_scope(engagement_id, value):
            raise PermissionError(f"asset is outside registered engagement scope: {value}")
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR IGNORE INTO assets(engagement_id,asset_type,value,metadata,created_at) VALUES(?,?,?,?,?)", (engagement_id, asset_type, value, json.dumps(metadata or {}, sort_keys=True), self._now()))
        return {"engagement_id": engagement_id, "asset_type": asset_type, "value": value, "metadata": metadata or {}, "in_scope": True}

    def list_assets(self, engagement_id: str) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT asset_type,value,metadata,created_at FROM assets WHERE engagement_id=? ORDER BY asset_type,value", (engagement_id,)).fetchall()
        return [{"asset_type": r[0], "value": r[1], "metadata": json.loads(r[2]), "created_at": r[3]} for r in rows]

    def create_finding(self, engagement_id: str, *, title: str, severity: str, description: str, remediation: str, asset_value: str | None = None, cwe: str | None = None, cvss: float | None = None, evidence: list[str] | None = None) -> dict[str, Any]:
        if asset_value and not self.in_scope(engagement_id, asset_value):
            raise PermissionError("finding asset is outside registered engagement scope")
        with sqlite3.connect(self.path) as db:
            count = db.execute("SELECT COUNT(*) FROM findings WHERE engagement_id=?", (engagement_id,)).fetchone()[0]
            finding_id = f"{engagement_id}-F{count + 1:04d}"
            now = self._now()
            db.execute("INSERT INTO findings(finding_id,engagement_id,title,severity,status,asset_value,cwe,cvss,evidence,description,remediation,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (finding_id, engagement_id, title, severity, "open", asset_value, cwe, cvss, json.dumps(evidence or []), description, remediation, now, now))
        return self.get_finding(finding_id)

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT finding_id,engagement_id,title,severity,status,asset_value,cwe,cvss,evidence,description,remediation,created_at,updated_at FROM findings WHERE finding_id=?", (finding_id,)).fetchone()
        if not row:
            raise KeyError(finding_id)
        keys = ["finding_id","engagement_id","title","severity","status","asset_value","cwe","cvss","evidence","description","remediation","created_at","updated_at"]
        data = dict(zip(keys, row)); data["evidence"] = json.loads(data["evidence"])
        return data

    def assessment_plan(self, engagement_id: str) -> dict[str, Any]:
        engagement = self.get_engagement(engagement_id)
        assets = self.list_assets(engagement_id)
        by_type: dict[str, int] = {}
        for asset in assets:
            by_type[asset["asset_type"]] = by_type.get(asset["asset_type"], 0) + 1
        steps = [
            {"phase": "scope-validation", "purpose": "Reconfirm registered scope and exclusions before assessment activity."},
            {"phase": "inventory", "purpose": "Normalize approved assets and technology metadata."},
            {"phase": "review", "purpose": "Prioritize assets for authorized security review using registered capabilities."},
            {"phase": "validation", "purpose": "Validate candidate findings and preserve evidence."},
            {"phase": "reporting", "purpose": "Create evidence-linked findings, remediation guidance, and retest records."},
        ]
        return {"version": self.VERSION, "engagement": engagement, "asset_count": len(assets), "assets_by_type": by_type, "steps": steps, "execution": "requires explicit operator-selected adapters and engagement authorization"}
