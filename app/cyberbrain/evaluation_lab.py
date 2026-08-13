from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class EvaluationScenario:
    scenario_id: str
    name: str
    domain: str
    description: str
    expected: dict[str, Any]
    tags: list[str] | None = None
    difficulty: str = "medium"


@dataclass(slots=True)
class EvaluationResult:
    scenario_id: str
    system: str
    passed: bool
    score: float
    grounded_rate: float | None = None
    false_positive_rate: float | None = None
    duration_ms: float | None = None
    tool_calls: int | None = None
    human_interventions: int | None = None
    notes: str | None = None


class EvaluationLab:
    VERSION = "X11.0"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS scenarios(id TEXT PRIMARY KEY,payload TEXT,created_at TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY AUTOINCREMENT,scenario_id TEXT,system TEXT,passed INTEGER,score REAL,payload TEXT,created_at TEXT)")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def upsert_scenario(self, scenario: EvaluationScenario) -> dict[str, Any]:
        payload = asdict(scenario)
        with sqlite3.connect(self.path) as db:
            db.execute("INSERT OR REPLACE INTO scenarios(id,payload,created_at) VALUES(?,?,?)", (scenario.scenario_id, json.dumps(payload, sort_keys=True), self._now()))
        return payload

    def scenarios(self, domain: str | None = None) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT payload,created_at FROM scenarios ORDER BY id").fetchall()
        out = []
        for raw, created_at in rows:
            item = json.loads(raw)
            if domain and item.get("domain") != domain:
                continue
            item["created_at"] = created_at
            out.append(item)
        return out

    def record(self, result: EvaluationResult) -> dict[str, Any]:
        if not 0 <= float(result.score) <= 1:
            raise ValueError("score must be between 0 and 1")
        with sqlite3.connect(self.path) as db:
            if not db.execute("SELECT 1 FROM scenarios WHERE id=?", (result.scenario_id,)).fetchone():
                raise KeyError(result.scenario_id)
            payload = asdict(result)
            db.execute("INSERT INTO results(scenario_id,system,passed,score,payload,created_at) VALUES(?,?,?,?,?,?)", (result.scenario_id, result.system, int(result.passed), result.score, json.dumps(payload, sort_keys=True), self._now()))
        return payload

    def leaderboard(self) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as db:
            rows = db.execute("SELECT system,COUNT(*),AVG(score),AVG(passed) FROM results GROUP BY system ORDER BY AVG(score) DESC").fetchall()
        return [{"system": r[0], "runs": int(r[1]), "mean_score": round(float(r[2] or 0), 4), "pass_rate": round(float(r[3] or 0), 4)} for r in rows]

    def summary(self) -> dict[str, Any]:
        with sqlite3.connect(self.path) as db:
            scenarios = db.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
            results = db.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        return {"version": self.VERSION, "scenario_count": scenarios, "result_count": results, "policy": {"reproducible_scenarios": True, "quality_metrics_persisted": True, "production_actions": False}}
