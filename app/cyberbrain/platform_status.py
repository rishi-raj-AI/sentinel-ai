from __future__ import annotations

from pathlib import Path
from typing import Any

from app.cyberbrain.evaluation_lab import EvaluationLab
from app.cyberbrain.shared_insights import SharedInsightStore


def sentinel_x_status(data_root: str | Path = "data") -> dict[str, Any]:
    root = Path(data_root)
    lab = EvaluationLab(root / "evaluation_lab.db")
    insights = SharedInsightStore(root / "shared_insights.json", minimum_sources=2)
    return {
        "platform": "Sentinel X",
        "generation": "X12",
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
        "evaluation": lab.summary(),
        "shared_insights": insights.stats(),
        "policy": {
            "evidence_grounding_preserved": True,
            "human_approval_supported": True,
            "simulation_preferred_for_path_analysis": True,
            "shared_insights_deidentified": True,
        },
    }
