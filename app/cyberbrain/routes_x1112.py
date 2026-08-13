from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.cyberbrain.evaluation_lab import EvaluationLab, EvaluationResult, EvaluationScenario
from app.cyberbrain.platform_status import sentinel_x_status
from app.cyberbrain.shared_insights import SharedInsight, SharedInsightStore
from app.enterprise.workspace import RBAC


class ScenarioBody(BaseModel):
    scenario_id: str
    name: str
    domain: str
    description: str
    expected: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    difficulty: str = "medium"


class ResultBody(BaseModel):
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


class InsightBody(BaseModel):
    category: str
    summary: str
    confidence: float
    frequency: int
    source_count: int
    attributes: dict[str, Any] = Field(default_factory=dict)


def _require(role: str, permission: str) -> None:
    try:
        RBAC.require(role, permission)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def install_x1112_routes(app: FastAPI, *, data_root: str = "data") -> None:
    root = Path(data_root)
    evaluation = EvaluationLab(root / "evaluation_lab.db")
    insights = SharedInsightStore(root / "shared_insights.json")

    @app.get("/api/x/status")
    def platform_status(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return sentinel_x_status(root)

    @app.get("/api/x/evaluation/summary")
    def evaluation_summary(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return evaluation.summary()

    @app.get("/api/x/evaluation/scenarios")
    def evaluation_scenarios(domain: str | None = None, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"scenarios": evaluation.scenarios(domain=domain)}

    @app.post("/api/x/evaluation/scenarios")
    def evaluation_upsert(body: ScenarioBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "review.write")
        return evaluation.upsert_scenario(EvaluationScenario(**body.model_dump()))

    @app.post("/api/x/evaluation/results")
    def evaluation_record(body: ResultBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "review.write")
        try:
            return evaluation.record(EvaluationResult(**body.model_dump()))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="scenario not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/x/evaluation/leaderboard")
    def evaluation_leaderboard(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"leaderboard": evaluation.leaderboard()}

    @app.get("/api/x/insights/stats")
    def insight_stats(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return insights.stats()

    @app.get("/api/x/insights")
    def insight_list(category: str | None = None, limit: int = 100, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"insights": insights.list(category=category, limit=limit)}

    @app.post("/api/x/insights")
    def insight_add(body: InsightBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "review.write")
        try:
            return insights.add(SharedInsight(**body.model_dump()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
