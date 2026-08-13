from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel

from app.enterprise.core import InvestigationReasoningService, KnowledgeGraphService
from app.enterprise.workspace import RBAC, WorkspaceStore, replay_events
from app.forensics.case_manager import CaseManager


class WorkspaceRequest(BaseModel):
    kind: str
    actor: str
    fields: dict[str, Any] = {}


class HypothesisRequest(BaseModel):
    hypothesis: str
    supporting: list[str] = []
    contradicting: list[str] = []
    gaps: list[str] = []
    source_quality: float = 0.8


def install_enterprise_routes(app: FastAPI, *, cases_root: str = "cases") -> None:
    router = APIRouter(prefix="/api/enterprise", tags=["enterprise"])
    manager = CaseManager(cases_root)

    def case_dir(case_id: str) -> Path:
        try: manager.load_case(case_id)
        except Exception as exc: raise HTTPException(status_code=404, detail=str(exc)) from exc
        return manager.root / case_id

    def require(role: str, permission: str) -> None:
        try: RBAC.require(role, permission)
        except PermissionError as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/graph")
    def graph(case_id: str, x_sentinel_role: str = Header(default="viewer")):
        require(x_sentinel_role, "graph.read")
        return KnowledgeGraphService(case_dir(case_id)).snapshot()

    @router.get("/cases/{case_id}/graph/neighbors")
    def neighbors(case_id: str, node_id: str, depth: int = Query(default=1, ge=1, le=5), x_sentinel_role: str = Header(default="viewer")):
        require(x_sentinel_role, "graph.read")
        return KnowledgeGraphService(case_dir(case_id)).neighbors(node_id, depth=depth)

    @router.get("/cases/{case_id}/graph/path")
    def path(case_id: str, source: str, target: str, x_sentinel_role: str = Header(default="viewer")):
        require(x_sentinel_role, "graph.read")
        return KnowledgeGraphService(case_dir(case_id)).shortest_path(source, target)

    @router.get("/correlate")
    def correlate(value: str, x_sentinel_role: str = Header(default="viewer")):
        require(x_sentinel_role, "graph.read")
        dirs = [p for p in manager.root.iterdir() if p.is_dir() and (p / "case.json").is_file()] if manager.root.exists() else []
        return KnowledgeGraphService.cross_case_correlate(dirs, value)

    @router.post("/cases/{case_id}/hypotheses/score")
    def score(case_id: str, request: HypothesisRequest, x_sentinel_role: str = Header(default="analyst")):
        require(x_sentinel_role, "case.read")
        return InvestigationReasoningService(case_dir(case_id)).score_hypothesis(**request.model_dump())

    @router.get("/cases/{case_id}/workspace")
    def workspace(case_id: str, x_sentinel_role: str = Header(default="viewer")):
        return WorkspaceStore(case_dir(case_id)).snapshot(role=x_sentinel_role)

    @router.post("/cases/{case_id}/workspace")
    def workspace_add(case_id: str, request: WorkspaceRequest, x_sentinel_role: str = Header(default="analyst")):
        try: return WorkspaceStore(case_dir(case_id)).add(request.kind, actor=request.actor, role=x_sentinel_role, **request.fields)
        except (PermissionError, ValueError) as exc: raise HTTPException(status_code=403 if isinstance(exc, PermissionError) else 400, detail=str(exc)) from exc

    @router.get("/cases/{case_id}/replay")
    def replay(case_id: str, x_sentinel_role: str = Header(default="viewer")):
        require(x_sentinel_role, "workspace.read")
        return {"case_id": case_id, "events": replay_events(case_dir(case_id))}

    @router.get("/rbac")
    def rbac():
        from app.enterprise.workspace import ROLE_PERMISSIONS
        return {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()}

    app.include_router(router)
