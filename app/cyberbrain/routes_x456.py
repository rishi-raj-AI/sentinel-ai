from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.cyberbrain.artifact_analysis import ArtifactAnalysisEngine
from app.cyberbrain.engagements import EngagementStore
from app.cyberbrain.privilege_graph import Principal, PrivilegeEdge, PrivilegeGraphStore
from app.cyberbrain.review_workflow import ReviewWorkflow
from app.enterprise.workspace import RBAC


class ReviewBody(BaseModel):
    objective: str


class ArtifactBody(BaseModel):
    filename: str


class PrivilegeBody(BaseModel):
    principals: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


def _require(role: str, permission: str) -> None:
    try:
        RBAC.require(role, permission)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def install_x456_routes(app: FastAPI, *, data_root: str = "data") -> None:
    root = Path(data_root)
    engagements = EngagementStore(root / "engagements.db")
    workflow = ReviewWorkflow(engagements)
    artifacts_root = (root / "artifacts").resolve()
    artifacts_root.mkdir(parents=True, exist_ok=True)
    artifact_engine = ArtifactAnalysisEngine()
    privileges = PrivilegeGraphStore(root / "privilege_graph.db")

    @app.post("/api/x/engagements/{engagement_id}/review-plan")
    def review_plan(engagement_id: str, body: ReviewBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return workflow.plan(engagement_id, body.objective)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="engagement not found") from exc

    @app.post("/api/x/artifacts/analyze")
    def artifact_analyze(body: ArtifactBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        candidate = (artifacts_root / body.filename).resolve()
        if artifacts_root not in candidate.parents:
            raise HTTPException(status_code=400, detail="artifact path must stay within configured artifact directory")
        try:
            return artifact_engine.analyze(candidate)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="artifact not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/x/privileges/ingest")
    def privilege_ingest(body: PrivilegeBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        try:
            principals = [Principal(**row) for row in body.principals]
            edges = [PrivilegeEdge(**row) for row in body.edges]
        except TypeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid privilege record: {exc}") from exc
        return privileges.ingest(principals, edges)

    @app.get("/api/x/privileges/stats")
    def privilege_stats(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return privileges.stats()

    @app.get("/api/x/privileges/risky")
    def privilege_risky(minimum_risk: float = 0.6, limit: int = 100, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"minimum_risk": minimum_risk, "edges": privileges.risky_edges(minimum_risk=minimum_risk, limit=limit)}

    @app.get("/api/x/privileges/path")
    def privilege_path(source_id: str, target_id: str, max_depth: int = 8, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return privileges.shortest_path(source_id, target_id, max_depth=max_depth)
