from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse

from app.autonomy.phase7 import MissionOperations
from app.enterprise.workspace import RBAC


def _require(role: str, permission: str) -> None:
    try:
        RBAC.require(role, permission)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


def install_operations_routes(app: FastAPI, *, data_root: str = "data") -> None:
    operations = MissionOperations(Path(data_root))

    @app.get("/api/x/operations/capabilities")
    def capability_plan(objective: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        if not objective.strip():
            raise HTTPException(status_code=400, detail="objective is required")
        return operations.capabilities.plan(objective)

    @app.get("/api/x/operations/missions/{mission_id}")
    def mission_snapshot(mission_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            return operations.snapshot(mission_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="mission not found") from exc

    @app.get("/api/x/operations/missions/{mission_id}/events")
    def mission_events(mission_id: str, limit: int = 500, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            operations.phase6.get_mission(mission_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="mission not found") from exc
        return {"mission_id": mission_id, "events": operations.events(mission_id, limit=limit)}

    @app.get("/api/x/operations/missions/{mission_id}/evidence")
    def mission_evidence(mission_id: str, x_sentinel_role: str = Header(default="viewer")):
        _require(x_sentinel_role, "case.read")
        try:
            operations.phase6.get_mission(mission_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="mission not found") from exc
        return {"mission_id": mission_id, "evidence": operations.evidence(mission_id)}

    @app.get("/api/x/operations/missions/{mission_id}/stream")
    async def mission_stream(mission_id: str):
        try:
            operations.phase6.get_mission(mission_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="mission not found") from exc

        async def generate():
            previous = ""
            heartbeat = 0
            while True:
                snapshot = operations.snapshot(mission_id)
                serialized = json.dumps(snapshot, sort_keys=True, default=str)
                if serialized != previous:
                    yield f"event: snapshot\ndata: {serialized}\n\n"
                    previous = serialized
                    heartbeat = 0
                else:
                    heartbeat += 1
                    if heartbeat >= 10:
                        yield ": heartbeat\n\n"
                        heartbeat = 0
                await asyncio.sleep(1.5)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
