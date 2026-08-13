from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.enterprise.workspace import RBAC
from app.tools.manager import ToolManager


class ToolPlanBody(BaseModel):
    objective: str


class ToolInstallBody(BaseModel):
    tool_id: str
    actor: str = "operator"
    confirmed: bool = False


def _require(role: str, permission: str) -> None:
    try:
        RBAC.require(role, permission)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def install_tool_routes(app: FastAPI, *, data_root: str = "data") -> None:
    manager = ToolManager(Path(data_root))

    @app.get("/api/x/tools")
    def tool_inventory(x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        return manager.inventory()

    @app.post("/api/x/tools/plan")
    def tool_plan(body: ToolPlanBody, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return manager.plan(body.objective)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/x/tools/install")
    def tool_install(body: ToolInstallBody, x_sentinel_role: str = Header(default="viewer")):
        if x_sentinel_role != "admin":
            raise HTTPException(status_code=403, detail="admin role required for tool installation")
        try:
            return manager.install(body.tool_id, actor=body.actor, confirmed=body.confirmed)
        except PermissionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=424, detail=str(exc)) from exc
        except TimeoutError as exc:
            raise HTTPException(status_code=504, detail=str(exc)) from exc

    @app.get("/api/x/tools/audit")
    def tool_audit(limit: int = 100, x_sentinel_role: str = Header(default="viewer")):
        if x_sentinel_role != "admin":
            raise HTTPException(status_code=403, detail="admin role required for tool-manager audit")
        return {"events": manager.audit(limit=limit)}
