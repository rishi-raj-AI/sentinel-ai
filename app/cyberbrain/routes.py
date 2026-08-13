from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.cyberbrain.core import CyberBrain, SkillRegistry
from app.cyberbrain.engagements import EngagementStore, ScopeRule
from app.cyberbrain.knowledge_store import KnowledgeEntity, KnowledgeRelation, KnowledgeStore
from app.enterprise.workspace import RBAC


class PlanBody(BaseModel):
    objective: str
    scoped_engagement: bool = False
    permissions: list[str] = Field(default_factory=lambda: ["case.read"])


class KnowledgeBody(BaseModel):
    entities: list[dict[str, Any]] = Field(default_factory=list)
    relations: list[dict[str, Any]] = Field(default_factory=list)


class EngagementBody(BaseModel):
    engagement_id: str
    name: str
    owner: str
    rules: list[dict[str, Any]]
    expires_at: str | None = None


class AssetBody(BaseModel):
    asset_type: str
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingBody(BaseModel):
    title: str
    severity: str
    description: str
    remediation: str
    asset_value: str | None = None
    cwe: str | None = None
    cvss: float | None = None
    evidence: list[str] = Field(default_factory=list)


def _require(role: str, permission: str) -> None:
    try:
        RBAC.require(role, permission)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def install_x_routes(app: FastAPI, *, data_root: str = "data") -> None:
    root = Path(data_root)
    registry = SkillRegistry()
    brain = CyberBrain(registry)
    knowledge = KnowledgeStore(root / "cyber_knowledge.db")
    engagements = EngagementStore(root / "engagements.db")

    @app.get("/api/x/skills")
    def skills(domain: str | None = None, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"version": registry.VERSION, "skills": registry.list(domain=domain)}

    @app.post("/api/x/plan")
    def plan(body: PlanBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return asdict(brain.plan(body.objective, available_permissions=body.permissions, scoped_engagement=body.scoped_engagement))

    @app.get("/api/x/knowledge/stats")
    def knowledge_stats(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return knowledge.stats()

    @app.get("/api/x/knowledge/search")
    def knowledge_search(q: str, entity_type: str | None = None, limit: int = 50, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"query": q, "matches": knowledge.search(q, entity_type=entity_type, limit=limit)}

    @app.post("/api/x/knowledge/ingest")
    def knowledge_ingest(body: KnowledgeBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        try:
            entities = [KnowledgeEntity(**row) for row in body.entities]
            relations = [KnowledgeRelation(**row) for row in body.relations]
        except TypeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid knowledge record: {exc}") from exc
        return knowledge.ingest(entities=entities, relations=relations)

    @app.get("/api/x/knowledge/{entity_id}/neighbors")
    def knowledge_neighbors(entity_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return {"entity_id": entity_id, "relations": knowledge.neighbors(entity_id)}

    @app.post("/api/x/engagements")
    def engagement_create(body: EngagementBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        try:
            return engagements.create_engagement(body.engagement_id, body.name, body.owner, [ScopeRule(**r) for r in body.rules], expires_at=body.expires_at)
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/x/engagements/{engagement_id}")
    def engagement_get(engagement_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return engagements.get_engagement(engagement_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="engagement not found") from exc

    @app.get("/api/x/engagements/{engagement_id}/scope")
    def scope_check(engagement_id: str, value: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return {"engagement_id": engagement_id, "value": value, "in_scope": engagements.in_scope(engagement_id, value)}
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="engagement not found") from exc

    @app.post("/api/x/engagements/{engagement_id}/assets")
    def asset_add(engagement_id: str, body: AssetBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        try:
            return engagements.add_asset(engagement_id, body.asset_type, body.value, metadata=body.metadata)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="engagement not found") from exc

    @app.get("/api/x/engagements/{engagement_id}/assets")
    def asset_list(engagement_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return engagements.list_assets(engagement_id)

    @app.get("/api/x/engagements/{engagement_id}/plan")
    def engagement_plan(engagement_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return engagements.assessment_plan(engagement_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="engagement not found") from exc

    @app.post("/api/x/engagements/{engagement_id}/findings")
    def finding_create(engagement_id: str, body: FindingBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "workspace.write")
        try:
            return engagements.create_finding(engagement_id, **body.model_dump())
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="engagement not found") from exc
