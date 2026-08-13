from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


ROLE_PERMISSIONS = {
    "viewer": {"case.read", "graph.read", "workspace.read"},
    "analyst": {"case.read", "graph.read", "workspace.read", "workspace.write", "job.run"},
    "lead": {"case.read", "graph.read", "workspace.read", "workspace.write", "job.run", "case.assign", "review.write"},
    "admin": {"*"},
}


class RBAC:
    @staticmethod
    def allowed(role: str, permission: str) -> bool:
        perms = ROLE_PERMISSIONS.get(role, set())
        return "*" in perms or permission in perms

    @classmethod
    def require(cls, role: str, permission: str) -> None:
        if not cls.allowed(role, permission):
            raise PermissionError(f"role '{role}' lacks permission '{permission}'")


class WorkspaceStore:
    """Per-case collaboration state with append-only activity history."""

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.path = self.case_dir / "workspace.json"

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"notes": [], "bookmarks": [], "tasks": [], "assignments": [], "reviews": [], "activity": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for key in ("notes", "bookmarks", "tasks", "assignments", "reviews", "activity"):
            data.setdefault(key, [])
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _stamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def add(self, kind: str, *, actor: str, role: str = "analyst", **fields: Any) -> dict[str, Any]:
        RBAC.require(role, "workspace.write")
        key = {"note":"notes", "bookmark":"bookmarks", "task":"tasks", "assignment":"assignments", "review":"reviews"}.get(kind)
        if not key:
            raise ValueError(f"unsupported workspace item kind: {kind}")
        if kind == "assignment": RBAC.require(role, "case.assign")
        if kind == "review": RBAC.require(role, "review.write")
        data = self._load()
        item = {"id": f"{kind.upper()}-{len(data[key])+1:04d}", "actor": actor, "created_at": self._stamp(), **fields}
        data[key].append(item)
        data["activity"].append({"timestamp": self._stamp(), "actor": actor, "action": f"workspace.{kind}.create", "item_id": item["id"]})
        self._save(data)
        return item

    def snapshot(self, *, role: str = "viewer") -> dict[str, Any]:
        RBAC.require(role, "workspace.read")
        return self._load()


class JobStore:
    """Persistent job abstraction. Execution is explicit; storage is durable SQLite."""
    def __init__(self, path: str | Path = "logs/jobs.db") -> None:
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as c:
            c.execute("CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, name TEXT, state TEXT, arguments TEXT, result TEXT, error TEXT)")

    def submit(self, name: str, arguments: dict[str, Any]) -> int:
        with sqlite3.connect(self.path) as c:
            cur = c.execute("INSERT INTO jobs(created_at,name,state,arguments) VALUES(?,?,?,?)", (datetime.now(timezone.utc).isoformat(), name, "queued", json.dumps(arguments, sort_keys=True)))
            return int(cur.lastrowid)

    def run(self, job_id: int, fn: Callable[..., Any]) -> dict[str, Any]:
        with sqlite3.connect(self.path) as c:
            row = c.execute("SELECT arguments FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not row: raise KeyError(job_id)
            args = json.loads(row[0]); c.execute("UPDATE jobs SET state='running' WHERE id=?", (job_id,))
        try:
            result = fn(**args)
            with sqlite3.connect(self.path) as c: c.execute("UPDATE jobs SET state='completed', result=? WHERE id=?", (json.dumps(result, default=str), job_id))
            return {"job_id": job_id, "state": "completed", "result": result}
        except Exception as exc:
            with sqlite3.connect(self.path) as c: c.execute("UPDATE jobs SET state='failed', error=? WHERE id=?", (str(exc), job_id))
            raise


@dataclass(slots=True)
class PluginSpec:
    name: str
    version: str
    description: str
    read_only: bool = True


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, tuple[PluginSpec, Callable[..., Any]]] = {}

    def register(self, spec: PluginSpec, handler: Callable[..., Any]) -> None:
        if spec.name in self._plugins: raise ValueError(f"plugin already registered: {spec.name}")
        self._plugins[spec.name] = (spec, handler)

    def list(self) -> list[dict[str, Any]]:
        return [asdict(spec) for spec, _ in self._plugins.values()]

    def invoke(self, name: str, **kwargs: Any) -> Any:
        if name not in self._plugins: raise KeyError(name)
        return self._plugins[name][1](**kwargs)


def _append_run_events(rows: list[dict[str, Any]], directory: Path, pattern: str, *, actor: str, action: str) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.glob(pattern)):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows.append({
            "timestamp": payload.get("created_at") or payload.get("started_at"),
            "actor": actor,
            "action": action,
            "item_id": payload.get("run_id"),
        })


def replay_events(case_dir: str | Path) -> list[dict[str, Any]]:
    case_path = Path(case_dir)
    rows = WorkspaceStore(case_path).snapshot(role="viewer").get("activity", [])
    _append_run_events(rows, case_path / "investigations", "*.json", actor="sentinel-agent", action="investigation.run")
    _append_run_events(rows, case_path / "soc_runs", "SOC-*.json", actor="sentinel-soc", action="soc.run")
    return sorted(rows, key=lambda x: str(x.get("timestamp") or ""))
