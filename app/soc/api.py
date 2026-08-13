from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.enterprise.workspace import RBAC
from app.soc.core_v2 import SOCSupervisor


class SOCRunRequest(BaseModel):
    objective: str


def _case_dir(cases_root: str, case_id: str) -> Path:
    path = Path(cases_root) / case_id
    if not (path / "case.json").is_file():
        raise HTTPException(status_code=404, detail=f"case not found: {case_id}")
    return path


def install_soc_routes(app: FastAPI, *, cases_root: str = "cases", sigma_rules: str = "rules/sigma") -> None:
    @app.get("/api/soc/agents")
    def list_agents():
        return {
            "version": "5.1",
            "agents": [
                {"name": "network-analyst", "specialty": "network"},
                {"name": "detection-analyst", "specialty": "sigma+yara"},
                {"name": "memory-analyst", "specialty": "memory"},
                {"name": "threat-hunter", "specialty": "attack+graph"},
                {"name": "counter-evidence-agent", "specialty": "contradiction"},
                {"name": "soc-supervisor", "specialty": "reconciliation"},
            ],
            "guardrails": {"read_only": True, "endpoint_remediation": False},
            "quality": {
                "counter_evidence_confidence": "weighted_top_relevance",
                "generic_event_penalty": True,
                "strict_synthesis_contract": True,
            },
        }

    @app.get("/api/soc/cases/{case_id}/runs")
    def list_runs(case_id: str, x_sentinel_role: str = Header(default="viewer")):
        try:
            RBAC.require(x_sentinel_role, "case.read")
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return SOCSupervisor(_case_dir(cases_root, case_id), sigma_rules=sigma_rules).list_runs()

    @app.get("/api/soc/cases/{case_id}/runs/{run_id}")
    def get_run(case_id: str, run_id: str, x_sentinel_role: str = Header(default="viewer")):
        try:
            RBAC.require(x_sentinel_role, "case.read")
            return SOCSupervisor(_case_dir(cases_root, case_id), sigma_rules=sigma_rules).load_run(run_id)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=f"SOC run not found: {run_id}") from exc

    @app.post("/api/soc/cases/{case_id}/runs")
    def create_run(case_id: str, body: SOCRunRequest, x_sentinel_role: str = Header(default="viewer")):
        try:
            RBAC.require(x_sentinel_role, "job.run")
            return SOCSupervisor(_case_dir(cases_root, case_id), sigma_rules=sigma_rules).run(
                body.objective, role=x_sentinel_role, persist=True
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
