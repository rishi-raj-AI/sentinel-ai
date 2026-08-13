from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TenantPolicy:
    tenant_id: str
    name: str
    allowed_action_classes: list[str]
    maximum_autonomy: str = "read-only"
    approved_domains: list[str] | None = None
    approved_networks: list[str] | None = None
    data_region: str | None = None
    retention_days: int = 90
    require_human_approval: bool = True
    metadata: dict[str, Any] | None = None


class ControlPlaneStore:
    """Enterprise/government policy store for tenant isolation and action authorization."""

    VERSION = "X10.0"
    AUTONOMY_ORDER = {"read-only": 0, "analysis": 1, "validation": 2, "approved-action": 3}

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT,policy TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT,actor TEXT,action TEXT,decision TEXT,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)")

    def upsert(self, policy: TenantPolicy) -> dict[str, Any]:
        payload = asdict(policy)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR REPLACE INTO tenants(id,name,policy) VALUES(?,?,?)", (policy.tenant_id, policy.name, json.dumps(payload, sort_keys=True)))
        return payload

    def get(self, tenant_id: str) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT policy FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        if not row:
            raise KeyError(tenant_id)
        return json.loads(row[0])

    def authorize(self, tenant_id: str, *, action_class: str, requested_autonomy: str, actor: str = "sentinel") -> dict[str, Any]:
        policy = self.get(tenant_id)
        allowed_actions = set(policy.get("allowed_action_classes") or [])
        configured = self.AUTONOMY_ORDER.get(str(policy.get("maximum_autonomy") or "read-only"), 0)
        requested = self.AUTONOMY_ORDER.get(requested_autonomy, 99)
        action_allowed = action_class in allowed_actions or "*" in allowed_actions
        autonomy_allowed = requested <= configured
        human_required = bool(policy.get("require_human_approval")) and requested >= self.AUTONOMY_ORDER["validation"]
        allowed = action_allowed and autonomy_allowed and not human_required
        reason = "allowed"
        if not action_allowed:
            reason = "action-class-not-approved"
        elif not autonomy_allowed:
            reason = "requested-autonomy-exceeds-policy"
        elif human_required:
            reason = "human-approval-required"
        result = {"tenant_id":tenant_id,"action_class":action_class,"requested_autonomy":requested_autonomy,"allowed":allowed,"reason":reason,"human_approval_required":human_required}
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT INTO audit(tenant_id,actor,action,decision,details) VALUES(?,?,?,?,?)", (tenant_id,actor,action_class,"allowed" if allowed else "denied",json.dumps(result,sort_keys=True)))
        return result

    def audit(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT actor,action,decision,details,created_at FROM audit WHERE tenant_id=? ORDER BY id DESC LIMIT ?", (tenant_id,limit)).fetchall()
        return [{"actor":r[0],"action":r[1],"decision":r[2],"details":json.loads(r[3]),"created_at":r[4]} for r in rows]

    def stats(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            tenants = db.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
            audits = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
        return {"version":self.VERSION,"tenant_count":tenants,"audit_decisions":audits,"policy":{"tenant_isolation_foundation":True,"action_authorization":True,"human_approval_supported":True}}
