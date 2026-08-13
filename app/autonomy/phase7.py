from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.autonomy.phase6 import Phase6Autonomy
from app.tools.integration import ToolRegistry


@dataclass(slots=True)
class CapabilitySpec:
    capability_id: str
    name: str
    domain: str
    preferred_tools: list[str]
    evidence_types: list[str]


class CapabilityPlanner:
    """Maps mission intent to capabilities, then selects a ready implementation."""

    VERSION = "capability-planner-v1"

    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self.registry = registry or ToolRegistry()
        self.catalog = [
            CapabilitySpec("network-inventory", "Network & Service Inventory", "network", ["nmap", "rustscan"], ["services", "hosts"]),
            CapabilitySpec("http-inventory", "HTTP Surface Inventory", "web", ["httpx", "katana"], ["http_services", "technologies"]),
            CapabilitySpec("source-analysis", "Static Source Analysis", "appsec", ["semgrep"], ["code_findings"]),
            CapabilitySpec("dependency-audit", "Dependency & Configuration Audit", "appsec", ["trivy", "grype"], ["dependency_findings", "configuration_findings"]),
            CapabilitySpec("iac-audit", "Infrastructure-as-Code Audit", "appsec", ["checkov"], ["iac_findings"]),
            CapabilitySpec("packet-analysis", "Packet Capture Analysis", "dfir", ["tshark", "zeek"], ["flows", "network_logs"]),
            CapabilitySpec("memory-analysis", "Memory Image Analysis", "dfir", ["volatility3"], ["memory_metadata"]),
            CapabilitySpec("artifact-capabilities", "Artifact Capability Analysis", "reverse", ["capa"], ["capabilities"]),
            CapabilitySpec("binary-structure", "Binary Structure Analysis", "reverse", ["radare2"], ["sections", "imports", "symbols"]),
        ]

    def _required(self, objective: str) -> list[CapabilitySpec]:
        text = objective.casefold()
        wanted: list[str] = []
        if any(x in text for x in ("network", "host", "service", "asset")): wanted.append("network-inventory")
        if any(x in text for x in ("web", "http", "api", "website")): wanted.append("http-inventory")
        if any(x in text for x in ("source", "code", "repository", "appsec")): wanted.extend(["source-analysis", "dependency-audit"])
        if any(x in text for x in ("terraform", "iac", "cloudformation")): wanted.append("iac-audit")
        if any(x in text for x in ("pcap", "packet", "traffic", "network forensic")): wanted.append("packet-analysis")
        if any(x in text for x in ("memory", "ram", "memory image")): wanted.append("memory-analysis")
        if any(x in text for x in ("malware", "binary", "reverse", "executable", "sample")): wanted.extend(["artifact-capabilities", "binary-structure"])
        if not wanted: wanted.append("dependency-audit")
        seen: set[str] = set()
        return [c for c in self.catalog if c.capability_id in wanted and not (c.capability_id in seen or seen.add(c.capability_id))]

    def plan(self, objective: str) -> dict[str, Any]:
        health = {row["tool_id"]: row for row in self.registry.health()}
        capabilities = []
        for cap in self._required(objective):
            candidates = []
            selected = None
            for tool_id in cap.preferred_tools:
                row = health.get(tool_id, {})
                candidate = {"tool_id": tool_id, "ready": bool(row.get("ready")), "version": row.get("version"), "profiles": row.get("profiles", [])}
                candidates.append(candidate)
                if selected is None and candidate["ready"]:
                    selected = candidate
            capabilities.append({**asdict(cap), "selected_tool": selected, "candidates": candidates, "ready": selected is not None})
        return {
            "version": self.VERSION,
            "objective": objective,
            "capabilities": capabilities,
            "ready": all(x["ready"] for x in capabilities),
            "missing_capabilities": [x["capability_id"] for x in capabilities if not x["ready"]],
        }


class MissionOperations:
    """Persistent event/evidence/supervisor layer for Phase 7 Mission Control."""

    VERSION = "phase7-v1"

    def __init__(self, data_root: str | Path = "data") -> None:
        self.root = Path(data_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "phase7_operations.db"
        self.phase6 = Phase6Autonomy(self.root)
        self.capabilities = CapabilityPlanner()
        with sqlite3.connect(self.db_path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS mission_events(id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE, mission_id TEXT NOT NULL, created_at TEXT NOT NULL, kind TEXT NOT NULL, actor TEXT NOT NULL, stage_id TEXT, payload_json TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS evidence_index(evidence_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL, case_id TEXT, created_at TEXT NOT NULL, evidence_type TEXT NOT NULL, label TEXT NOT NULL, source TEXT, stage_id TEXT, confidence REAL, metadata_json TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS supervisor_state(mission_id TEXT PRIMARY KEY, updated_at TEXT NOT NULL, confidence REAL NOT NULL, coverage REAL NOT NULL, contradictions INTEGER NOT NULL, blockers INTEGER NOT NULL, verdict TEXT NOT NULL, notes_json TEXT NOT NULL)")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def emit(self, mission_id: str, kind: str, *, actor: str, stage_id: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        event = {"event_id": f"EV-{uuid.uuid4().hex[:12].upper()}", "mission_id": mission_id, "created_at": self._now(), "kind": kind, "actor": actor, "stage_id": stage_id, "payload": payload or {}}
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO mission_events(event_id,mission_id,created_at,kind,actor,stage_id,payload_json) VALUES(?,?,?,?,?,?,?)", (event["event_id"], mission_id, event["created_at"], kind, actor, stage_id, json.dumps(event["payload"], sort_keys=True)))
        return event

    def events(self, mission_id: str, limit: int = 500) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT event_id,created_at,kind,actor,stage_id,payload_json FROM mission_events WHERE mission_id=? ORDER BY id DESC LIMIT ?", (mission_id, max(1, min(limit, 2000)))).fetchall()
        return [{"event_id": r[0], "created_at": r[1], "kind": r[2], "actor": r[3], "stage_id": r[4], "payload": json.loads(r[5])} for r in reversed(rows)]

    def index_evidence(self, mission_id: str, *, evidence_type: str, label: str, source: str | None = None, stage_id: str | None = None, confidence: float | None = None, case_id: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        evidence_id = f"E-{uuid.uuid4().hex[:12].upper()}"
        row = {"evidence_id": evidence_id, "mission_id": mission_id, "case_id": case_id, "created_at": self._now(), "evidence_type": evidence_type, "label": label, "source": source, "stage_id": stage_id, "confidence": confidence, "metadata": metadata or {}}
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO evidence_index(evidence_id,mission_id,case_id,created_at,evidence_type,label,source,stage_id,confidence,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?)", (evidence_id, mission_id, case_id, row["created_at"], evidence_type, label, source, stage_id, confidence, json.dumps(row["metadata"], sort_keys=True)))
        self.emit(mission_id, "evidence.indexed", actor="evidence-indexer", stage_id=stage_id, payload={"evidence_id": evidence_id, "type": evidence_type, "label": label})
        return row

    def evidence(self, mission_id: str) -> list[dict[str, Any]]:
        with sqlite3.connect(self.db_path) as db:
            rows = db.execute("SELECT evidence_id,case_id,created_at,evidence_type,label,source,stage_id,confidence,metadata_json FROM evidence_index WHERE mission_id=? ORDER BY created_at", (mission_id,)).fetchall()
        return [{"evidence_id": r[0], "case_id": r[1], "created_at": r[2], "evidence_type": r[3], "label": r[4], "source": r[5], "stage_id": r[6], "confidence": r[7], "metadata": json.loads(r[8])} for r in rows]

    def refresh_supervisor(self, mission_id: str) -> dict[str, Any]:
        mission = self.phase6.get_mission(mission_id)
        stages = mission["plan"]["stages"]
        run_by_id = {r["stage_id"]: r for r in mission["stage_runs"]}
        completed = sum(1 for s in stages if run_by_id.get(s["stage_id"], {}).get("state") == "completed")
        failed = sum(1 for r in mission["stage_runs"] if r["state"] == "failed")
        indexed = self.evidence(mission_id)
        contradictions = sum(1 for e in indexed if e["metadata"].get("counter_evidence") is True)
        coverage = completed / len(stages) if stages else 0.0
        confidence = max(0.0, min(1.0, 0.45 + coverage * 0.45 + min(len(indexed), 10) * 0.01 - contradictions * 0.05 - failed * 0.15))
        blockers = failed + (1 if mission["status"] == "blocked" else 0)
        verdict = "ready-for-review" if coverage >= 0.75 and blockers == 0 else ("blocked" if blockers else "in-progress")
        notes = [
            f"{completed}/{len(stages)} stages completed",
            f"{len(indexed)} evidence records indexed",
            f"{contradictions} counter-evidence records preserved",
        ]
        row = {"mission_id": mission_id, "updated_at": self._now(), "confidence": round(confidence, 4), "coverage": round(coverage, 4), "contradictions": contradictions, "blockers": blockers, "verdict": verdict, "notes": notes}
        with sqlite3.connect(self.db_path) as db:
            db.execute("INSERT INTO supervisor_state(mission_id,updated_at,confidence,coverage,contradictions,blockers,verdict,notes_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(mission_id) DO UPDATE SET updated_at=excluded.updated_at,confidence=excluded.confidence,coverage=excluded.coverage,contradictions=excluded.contradictions,blockers=excluded.blockers,verdict=excluded.verdict,notes_json=excluded.notes_json", (mission_id, row["updated_at"], row["confidence"], row["coverage"], contradictions, blockers, verdict, json.dumps(notes)))
        return row

    def snapshot(self, mission_id: str) -> dict[str, Any]:
        mission = self.phase6.get_mission(mission_id)
        return {
            "version": self.VERSION,
            "mission": mission,
            "capability_plan": self.capabilities.plan(mission["objective"]),
            "events": self.events(mission_id),
            "evidence": self.evidence(mission_id),
            "supervisor": self.refresh_supervisor(mission_id),
        }
