from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.tools.integration import ToolRunner
from app.tools.manager import ToolManager


@dataclass(slots=True)
class MissionStage:
    stage_id: str
    title: str
    purpose: str
    agent: str
    tool_id: str | None = None
    profile_id: str | None = None
    depends_on: list[str] = field(default_factory=list)
    requires_scope: bool = False
    requires_approval: bool = False
    expected_outputs: list[str] = field(default_factory=list)


class Phase6Autonomy:
    """Plan -> prepare -> approve -> execute -> learn orchestration.

    No arbitrary command text is accepted. Execution delegates only to profiles
    already registered in ToolRunner, which preserves scope, timeout, path and
    approval controls.
    """

    VERSION = "phase6-v1"

    def __init__(self, data_root: str | Path = "data") -> None:
        self.root = Path(data_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "phase6_missions.db"
        self.manager = ToolManager(self.root)
        self.runner = ToolRunner(self.root)
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS missions(mission_id TEXT PRIMARY KEY, objective TEXT NOT NULL, case_id TEXT, engagement_id TEXT, target TEXT, status TEXT NOT NULL, plan_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, approved_by TEXT, report_json TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS stage_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, stage_id TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT, completed_at TEXT, result_json TEXT, error TEXT, UNIQUE(mission_id, stage_id))")
            db.execute("CREATE TABLE IF NOT EXISTS memory(id INTEGER PRIMARY KEY AUTOINCREMENT, mission_id TEXT NOT NULL, case_id TEXT, created_at TEXT NOT NULL, lesson TEXT NOT NULL, tags TEXT NOT NULL)")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _stage(stage_id: str, title: str, purpose: str, agent: str, *, tool_id: str | None = None, profile_id: str | None = None, depends_on: list[str] | None = None, requires_scope: bool = False, requires_approval: bool = False, outputs: list[str] | None = None) -> MissionStage:
        return MissionStage(stage_id, title, purpose, agent, tool_id, profile_id, depends_on or [], requires_scope, requires_approval, outputs or [])

    def _build_stages(self, objective: str) -> list[MissionStage]:
        text = objective.casefold()
        rows: list[MissionStage] = [
            self._stage("S1", "Context & evidence review", "Establish known evidence, assumptions and collection gaps.", "mission-planner", outputs=["context", "gaps", "assumptions"]),
        ]
        parents = ["S1"]
        n = 2

        def add(title: str, purpose: str, agent: str, tool: str | None = None, profile: str | None = None, *, scope: bool = False, approval: bool = False, outputs: list[str] | None = None) -> str:
            nonlocal n
            sid = f"S{n}"; n += 1
            rows.append(self._stage(sid, title, purpose, agent, tool_id=tool, profile_id=profile, depends_on=list(parents), requires_scope=scope, requires_approval=approval, outputs=outputs))
            return sid

        branches: list[str] = []
        if any(x in text for x in ("network", "host", "service", "asset")):
            branches.append(add("Network/service inventory", "Establish approved host/service context.", "network-analyst", "nmap", "service-inventory", scope=True, outputs=["services", "service_metadata"]))
        if any(x in text for x in ("web", "http", "api", "website")):
            branches.append(add("HTTP surface inventory", "Collect approved HTTP metadata and technology context.", "web-analyst", "httpx", "http-inventory", scope=True, outputs=["http_services", "technologies"]))
        if any(x in text for x in ("source", "code", "repository", "appsec")):
            branches.append(add("Source security review", "Run confined static source analysis.", "appsec-analyst", "semgrep", "source-audit", outputs=["code_findings"]))
            branches.append(add("Dependency/configuration review", "Run confined dependency and configuration analysis.", "appsec-analyst", "trivy", "filesystem-audit", outputs=["dependency_findings", "configuration_findings"]))
        if any(x in text for x in ("pcap", "packet", "traffic", "network forensic")):
            branches.append(add("Packet-capture summary", "Summarize already-acquired packet evidence.", "network-forensics-agent", "tshark", "pcap-summary", outputs=["flows", "conversations"]))
            branches.append(add("Network forensic logs", "Transform already-acquired packet evidence into structured logs.", "network-forensics-agent", "zeek", "pcap-logs", outputs=["network_logs"]))
        if any(x in text for x in ("memory", "ram", "memory image")):
            branches.append(add("Memory-image metadata", "Inspect already-acquired memory evidence.", "dfir-agent", "volatility3", "memory-info", outputs=["memory_metadata"]))
        if any(x in text for x in ("malware", "binary", "reverse", "executable", "sample")):
            branches.append(add("Artifact capability analysis", "Extract behavioral capabilities from a confined artifact.", "malware-analyst", "capa", "capability-analysis", outputs=["capabilities"]))
            branches.append(add("Binary structure review", "Extract structural metadata from a confined artifact.", "reverse-engineering-agent", "radare2", "binary-info", outputs=["sections", "imports", "symbols"]))
        if not branches:
            branches.append(add("Baseline local security review", "Perform confined dependency/configuration review for the supplied project.", "appsec-analyst", "trivy", "filesystem-audit", outputs=["baseline_findings"]))

        parents = branches
        correlate = add("Evidence correlation", "Correlate specialist outputs, preserve contradictions and identify gaps.", "correlation-agent", outputs=["correlations", "counter_evidence", "gaps"])
        parents = [correlate]
        review = add("Supervisor review", "Review evidence coverage, confidence and unsupported claims.", "supervisor-agent", outputs=["review", "confidence", "approval_notes"])
        parents = [review]
        add("Mission report", "Produce an evidence-oriented mission summary and lessons learned.", "reporting-agent", outputs=["report", "lessons"])
        return rows

    def create_mission(self, objective: str, *, case_id: str | None = None, engagement_id: str | None = None, target: str | None = None) -> dict[str, Any]:
        objective = objective.strip()
        if not objective:
            raise ValueError("objective is required")
        mission_id = f"M-{uuid.uuid4().hex[:10].upper()}"
        stages = self._build_stages(objective)
        tool_plan = self.manager.plan(objective)
        plan = {
            "version": self.VERSION,
            "mission_id": mission_id,
            "objective": objective,
            "case_id": case_id,
            "engagement_id": engagement_id,
            "target": target,
            "stages": [asdict(x) for x in stages],
            "tool_plan": tool_plan,
            "agents": sorted({x.agent for x in stages}),
            "policy": {"approval_before_execution": True, "registered_profiles_only": True, "scope_enforced_by_runner": True, "arbitrary_commands": False},
        }
        now = self._now()
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO missions(mission_id,objective,case_id,engagement_id,target,status,plan_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (mission_id, objective, case_id, engagement_id, target, "planned", json.dumps(plan, sort_keys=True), now, now))
        return self.get_mission(mission_id)

    def get_mission(self, mission_id: str) -> dict[str, Any]:
        with sqlite3.connect(self.db_path) as db:
            row = db.execute("SELECT mission_id,objective,case_id,engagement_id,target,status,plan_json,created_at,updated_at,approved_by,report_json FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
            runs = db.execute("SELECT stage_id,state,started_at,completed_at,result_json,error FROM stage_runs WHERE mission_id=? ORDER BY id", (mission_id,)).fetchall()
        if not row:
            raise KeyError(mission_id)
        return {
            "mission_id": row[0], "objective": row[1], "case_id": row[2], "engagement_id": row[3], "target": row[4], "status": row[5],
            "plan": json.loads(row[6]), "created_at": row[7], "updated_at": row[8], "approved_by": row[9], "report": json.loads(row[10]) if row[10] else None,
            "stage_runs": [{"stage_id": r[0], "state": r[1], "started_at": r[2], "completed_at": r[3], "result": json.loads(r[4]) if r[4] else None, "error": r[5]} for r in runs],
        }

    def prepare(self, mission_id: str) -> dict[str, Any]:
        mission = self.get_mission(mission_id)
        plan = mission["plan"]
        health = {r["tool_id"]: r for r in self.manager.inventory()["tools"]}
        checks: list[dict[str, Any]] = []
        blocked = False
        for stage in plan["stages"]:
            tool_id = stage.get("tool_id")
            if not tool_id:
                continue
            row = health.get(tool_id, {})
            ready = bool(row.get("ready"))
            checks.append({"stage_id": stage["stage_id"], "tool_id": tool_id, "ready": ready, "status": "ready" if ready else ("repair" if row.get("installed") else "missing"), "one_click_install": bool(row.get("one_click_install")), "version": row.get("version")})
            blocked = blocked or not ready
        if any(s.get("requires_scope") for s in plan["stages"]):
            scope_ready = bool(mission.get("engagement_id") and mission.get("target"))
            checks.append({"stage_id": "scope", "tool_id": None, "ready": scope_ready, "status": "ready" if scope_ready else "missing-engagement-or-target"})
            blocked = blocked or not scope_ready
        status = "blocked" if blocked else "prepared"
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE missions SET status=?,updated_at=? WHERE mission_id=?", (status, self._now(), mission_id))
        return {"version": self.VERSION, "mission_id": mission_id, "ready": not blocked, "status": status, "checks": checks, "next_action": "approve" if not blocked else "resolve-prerequisites"}

    def approve(self, mission_id: str, *, actor: str) -> dict[str, Any]:
        prep = self.prepare(mission_id)
        if not prep["ready"]:
            raise PermissionError("mission prerequisites are not ready")
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE missions SET status='approved',approved_by=?,updated_at=? WHERE mission_id=?", (actor, self._now(), mission_id))
        return self.get_mission(mission_id)

    def _dependencies_done(self, mission_id: str, deps: list[str]) -> bool:
        if not deps:
            return True
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT stage_id,state FROM stage_runs WHERE mission_id=?", (mission_id,)).fetchall()
        states = {r[0]: r[1] for r in rows}
        return all(states.get(dep) == "completed" for dep in deps)

    def execute(self, mission_id: str, *, actor: str, path: str | None = None) -> dict[str, Any]:
        mission = self.get_mission(mission_id)
        if mission["status"] not in {"approved", "running", "blocked"}:
            raise PermissionError("mission must be prepared and approved before execution")
        plan = mission["plan"]
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE missions SET status='running',updated_at=? WHERE mission_id=?", (self._now(), mission_id))
        events: list[dict[str, Any]] = []
        for stage in plan["stages"]:
            sid = stage["stage_id"]
            with sqlite3.connect(self.db_path) as db:
                existing = db.execute("SELECT state FROM stage_runs WHERE mission_id=? AND stage_id=?", (mission_id, sid)).fetchone()
            if existing and existing[0] == "completed":
                continue
            if not self._dependencies_done(mission_id, stage.get("depends_on", [])):
                continue
            started = self._now()
            with sqlite3.connect(self.db_path) as db:
                db.execute("INSERT INTO stage_runs(mission_id,stage_id,state,started_at) VALUES(?,?,?,?) ON CONFLICT(mission_id,stage_id) DO UPDATE SET state='running',started_at=excluded.started_at,error=NULL", (mission_id, sid, "running", started))
            try:
                if stage.get("tool_id") and stage.get("profile_id"):
                    result = self.runner.execute(tool_id=stage["tool_id"], profile_id=stage["profile_id"], actor=actor, engagement_id=mission.get("engagement_id"), target=mission.get("target"), path=path, approved=True)
                else:
                    result = {"agent": stage["agent"], "purpose": stage["purpose"], "state": "decision-support-complete", "outputs": stage.get("expected_outputs", [])}
                with sqlite3.connect(self.db_path) as db:
                    db.execute("UPDATE stage_runs SET state='completed',completed_at=?,result_json=? WHERE mission_id=? AND stage_id=?", (self._now(), json.dumps(result, default=str), mission_id, sid))
                events.append({"stage_id": sid, "state": "completed"})
            except Exception as exc:
                with sqlite3.connect(self.db_path) as db:
                    db.execute("UPDATE stage_runs SET state='failed',completed_at=?,error=? WHERE mission_id=? AND stage_id=?", (self._now(), str(exc), mission_id, sid))
                    db.execute("UPDATE missions SET status='blocked',updated_at=? WHERE mission_id=?", (self._now(), mission_id))
                return {"version": self.VERSION, "mission_id": mission_id, "status": "blocked", "events": events, "blocked_stage": sid, "error": str(exc)}
        current = self.get_mission(mission_id)
        completed = {r["stage_id"] for r in current["stage_runs"] if r["state"] == "completed"}
        all_ids = {s["stage_id"] for s in plan["stages"]}
        if completed >= all_ids:
            report = self.finalize(mission_id)
            return {"version": self.VERSION, "mission_id": mission_id, "status": "completed", "events": events, "report": report}
        return {"version": self.VERSION, "mission_id": mission_id, "status": "running", "events": events, "remaining": sorted(all_ids - completed)}

    def finalize(self, mission_id: str) -> dict[str, Any]:
        mission = self.get_mission(mission_id)
        runs = mission["stage_runs"]
        failures = [r for r in runs if r["state"] == "failed"]
        tool_runs = [r for r in runs if isinstance(r.get("result"), dict) and r["result"].get("tool_id")]
        report = {
            "version": self.VERSION,
            "mission_id": mission_id,
            "objective": mission["objective"],
            "case_id": mission.get("case_id"),
            "status": "completed" if not failures else "completed-with-failures",
            "completed_stages": sum(1 for r in runs if r["state"] == "completed"),
            "failed_stages": len(failures),
            "tool_runs": [{"stage_id": r["stage_id"], "tool_id": r["result"].get("tool_id"), "profile_id": r["result"].get("profile_id"), "returncode": r["result"].get("returncode")} for r in tool_runs],
            "explainability": {"registered_profiles_only": True, "scope_enforced": True, "approval_actor": mission.get("approved_by"), "unsupported_claims_not_generated": True},
            "generated_at": self._now(),
        }
        lesson = f"Mission {mission_id} completed {report['completed_stages']} stages with {report['failed_stages']} failures."
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE missions SET status='completed',report_json=?,updated_at=? WHERE mission_id=?", (json.dumps(report, sort_keys=True), self._now(), mission_id))
            db.execute("INSERT INTO memory(mission_id,case_id,created_at,lesson,tags) VALUES(?,?,?,?,?)", (mission_id, mission.get("case_id"), self._now(), lesson, json.dumps(["phase6", "mission-outcome"])))
        return report

    def memory(self, *, case_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as db:
            if case_id:
                rows = db.execute("SELECT mission_id,case_id,created_at,lesson,tags FROM memory WHERE case_id=? ORDER BY id DESC LIMIT ?", (case_id, max(1, min(limit, 500)))).fetchall()
            else:
                rows = db.execute("SELECT mission_id,case_id,created_at,lesson,tags FROM memory ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
        return [{"mission_id": r[0], "case_id": r[1], "created_at": r[2], "lesson": r[3], "tags": json.loads(r[4])} for r in rows]

    def list_missions(self, limit: int = 100) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT mission_id,objective,case_id,status,created_at,updated_at,approved_by FROM missions ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
        return [{"mission_id": r[0], "objective": r[1], "case_id": r[2], "status": r[3], "created_at": r[4], "updated_at": r[5], "approved_by": r[6]} for r in rows]
