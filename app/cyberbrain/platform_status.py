from __future__ import annotations

from pathlib import Path
from typing import Any

from app.cyberbrain.evaluation_lab import EvaluationLab
from app.cyberbrain.shared_insights import SharedInsightStore


def sentinel_x_status(data_root: str | Path = "data") -> dict[str, Any]:
    root = Path(data_root)
    lab = EvaluationLab(root / "evaluation_lab.db")
    insights = SharedInsightStore(root / "shared_insights.json", minimum_sources=2)
    stores = {
        "knowledge": root / "cyber_knowledge.db",
        "engagements": root / "engagements.db",
        "privileges": root / "privilege_graph.db",
        "digital_twin": root / "digital_twin.db",
        "control_plane": root / "control_plane.db",
        "evaluation": root / "evaluation_lab.db",
        "shared_insights": root / "shared_insights.json",
    }
    return {
        "platform": "Sentinel X",
        "generation": "X12",
        "backend_api_version": "1.0",
        "backend_ui_ready": True,
        "phases": {
            "X1": "cyber-brain",
            "X2": "knowledge-intelligence",
            "X3": "engagement-scope",
            "X4": "review-workflow",
            "X5": "artifact-analysis",
            "X6": "privilege-graph",
            "X7": "appsec-supply-chain",
            "X8": "digital-twin",
            "X9": "security-fusion",
            "X10": "control-plane",
            "X11": "evaluation-lab",
            "X12": "shared-insights",
        },
        "stores": {name: {"path": str(path), "exists": path.exists()} for name, path in stores.items()},
        "evaluation": lab.summary(),
        "shared_insights": insights.stats(),
        "policy": {
            "evidence_grounding_preserved": True,
            "human_approval_supported": True,
            "simulation_preferred_for_path_analysis": True,
            "shared_insights_deidentified": True,
            "frontend_credentials_forbidden": True,
        },
    }
