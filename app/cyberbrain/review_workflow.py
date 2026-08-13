from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.cyberbrain.engagements import EngagementStore


@dataclass(slots=True)
class ReviewTask:
    task_id: str
    role: str
    objective: str
    asset: str | None
    stage: str
    status: str = "planned"


class ReviewWorkflow:
    VERSION = "X4.0"
    ROLES = (
        ("asset-reviewer", "inventory"),
        ("application-reviewer", "application"),
        ("api-reviewer", "api"),
        ("identity-reviewer", "identity"),
        ("cloud-reviewer", "cloud"),
        ("finding-validator", "validation"),
        ("reporting-agent", "reporting"),
    )

    def __init__(self, engagements: EngagementStore) -> None:
        self.engagements = engagements

    def plan(self, engagement_id: str, objective: str) -> dict[str, Any]:
        engagement = self.engagements.get_engagement(engagement_id)
        assets = self.engagements.list_assets(engagement_id)
        tasks: list[ReviewTask] = []
        idx = 1
        for asset in assets:
            value = str(asset.get("value") or "")
            asset_type = str(asset.get("asset_type") or "").lower()
            if not value or not self.engagements.in_scope(engagement_id, value):
                continue
            tasks.append(ReviewTask(f"RW-{idx:04d}", "asset-reviewer", "Validate registered asset metadata and inventory coverage.", value, "inventory")); idx += 1
            if asset_type in {"domain", "url", "web", "application", "host"}:
                tasks.append(ReviewTask(f"RW-{idx:04d}", "application-reviewer", "Review supplied application metadata and documented boundaries.", value, "application")); idx += 1
                tasks.append(ReviewTask(f"RW-{idx:04d}", "api-reviewer", "Review supplied API metadata and documented boundaries.", value, "api")); idx += 1
            if asset_type in {"cloud", "subscription", "account", "tenant"}:
                tasks.append(ReviewTask(f"RW-{idx:04d}", "cloud-reviewer", "Review supplied cloud posture and relationships.", value, "cloud")); idx += 1
            if asset_type in {"identity", "directory", "tenant"}:
                tasks.append(ReviewTask(f"RW-{idx:04d}", "identity-reviewer", "Review supplied identity and relationship data.", value, "identity")); idx += 1
        tasks.append(ReviewTask(f"RW-{idx:04d}", "finding-validator", "Validate candidate findings against stored evidence.", None, "validation")); idx += 1
        tasks.append(ReviewTask(f"RW-{idx:04d}", "reporting-agent", "Assemble evidence-linked findings and remediation guidance.", None, "reporting"))
        return {
            "version": self.VERSION,
            "engagement_id": engagement_id,
            "engagement": engagement,
            "objective": objective,
            "roles": [{"name": n, "specialty": s} for n, s in self.ROLES],
            "tasks": [asdict(t) for t in tasks],
            "task_count": len(tasks),
            "policy": {"registered_scope_only": True, "read_only_planning": True},
        }
