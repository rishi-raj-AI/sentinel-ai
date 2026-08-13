from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.cyberbrain.appsec import AppSecAnalyzer
from app.cyberbrain.control_plane import ControlPlaneStore, TenantPolicy
from app.cyberbrain.digital_twin import DigitalTwinStore, TwinEdge, TwinNode
from app.cyberbrain.security_fusion import FusionSignal, SecurityFusionEngine
from app.enterprise.workspace import RBAC


class AppSecBody(BaseModel):
    project: str
    max_files: int = 5000


class TwinBody(BaseModel):
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


class FusionBody(BaseModel):
    objective: str = "Assess security posture"
    signals: list[dict[str, Any]] = Field(default_factory=list)


class TenantBody(BaseModel):
    tenant_id: str
    name: str
    allowed_action_classes: list[str]
    maximum_autonomy: str = "read-only"
    approved_domains: list[str] = Field(default_factory=list)
    approved_networks: list[str] = Field(default_factory=list)
    data_region: str | None = None
    retention_days: int = 90
    require_human_approval: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthorizeBody(BaseModel):
    action_class: str
    requested_autonomy: str = "read-only"
    actor: str = "sentinel"


def _require(role: str, permission: str) -> None:
    try:
        RBAC.require(role, permission)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def install_x78910_routes(app: FastAPI, *, data_root: str = "data") -> None:
    root = Path(data_root)
    appsec_root = (root / "projects").resolve()
    appsec_root.mkdir(parents=True, exist_ok=True)
    appsec = AppSecAnalyzer()
    twin = DigitalTwinStore(root / "digital_twin.db")
    fusion = SecurityFusionEngine()
    control = ControlPlaneStore(root / "control_plane.db")

    @app.post("/api/x/appsec/analyze")
    def appsec_analyze(body: AppSecBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        candidate = (appsec_root / body.project).resolve()
        if candidate != appsec_root and appsec_root not in candidate.parents:
            raise HTTPException(status_code=400, detail="project path must stay within configured project directory")
        try:
            return appsec.analyze(candidate, max_files=max(1, min(body.max_files, 20000)))
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="project not found") from exc

    @app.post("/api/x/twin/ingest")
    def twin_ingest(body: TwinBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        try:
            nodes = [TwinNode(**row) for row in body.nodes]
            edges = [TwinEdge(**row) for row in body.edges]
        except TypeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid twin record: {exc}") from exc
        return twin.ingest(nodes, edges)

    @app.get("/api/x/twin/coverage")
    def twin_coverage(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return twin.coverage()

    @app.get("/api/x/twin/simulate")
    def twin_simulate(source_id: str, target_type: str | None = None, max_depth: int = 6, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return twin.simulate_paths(source_id, target_type=target_type, max_depth=max(1,min(max_depth,10)))

    @app.post("/api/x/fusion/evaluate")
    def fusion_evaluate(body: FusionBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            signals = [FusionSignal(**row) for row in body.signals]
        except TypeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid signal: {exc}") from exc
        return fusion.fuse(signals, objective=body.objective)

    @app.post("/api/x/control/tenants")
    def tenant_upsert(body: TenantBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "review.write")
        try:
            return control.upsert(TenantPolicy(**body.model_dump()))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/x/control/tenants/{tenant_id}")
    def tenant_get(tenant_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return control.get(tenant_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="tenant not found") from exc

    @app.post("/api/x/control/tenants/{tenant_id}/authorize")
    def tenant_authorize(tenant_id: str, body: AuthorizeBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return control.authorize(tenant_id, action_class=body.action_class, requested_autonomy=body.requested_autonomy, actor=body.actor)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="tenant not found") from exc

    @app.get("/api/x/control/tenants/{tenant_id}/audit")
    def tenant_audit(tenant_id: str, limit: int = 100, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "review.write")
        return {"tenant_id":tenant_id,"decisions":control.audit(tenant_id,limit=max(1,min(limit,1000)))}

    @app.get("/api/x/control/stats")
    def control_stats(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return control.stats()
