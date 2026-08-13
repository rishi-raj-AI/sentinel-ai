from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.autonomy.phase7 import MissionOperations


class MissionIntelligenceV2:
    """Read-only Phase 8-11 intelligence projections over durable mission state.

    The service does not execute tools or mutate mission state. It derives replay,
    evidence, twin, review and historical-memory views from Phase 6/7 stores.
    """

    VERSION = "mission-intelligence-v2"

    def __init__(self, data_root: str | Path = "data") -> None:
        self.operations = MissionOperations(Path(data_root))

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {
            token
            for token in re.findall(r"[a-z0-9][a-z0-9._-]+", text.casefold())
            if len(token) > 2
        }

    @staticmethod
    def _score_overlap(left: set[str], right: set[str]) -> float:
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)

    def replay(self, mission_id: str) -> dict[str, Any]:
        snapshot = self.operations.snapshot(mission_id)
        mission = snapshot["mission"]
        stage_by_id = {s["stage_id"]: s for s in mission["plan"].get("stages", [])}
        frames: list[dict[str, Any]] = []

        frames.append(
            {
                "frame_id": "F-000",
                "at": mission["created_at"],
                "kind": "mission.created",
                "stage_id": None,
                "label": "Mission created",
                "actor": "mission-planner",
                "state": mission["status"],
            }
        )

        for run in mission.get("stage_runs", []):
            stage = stage_by_id.get(run["stage_id"], {})
            if run.get("started_at"):
                frames.append(
                    {
                        "frame_id": f"F-{run['stage_id']}-START",
                        "at": run["started_at"],
                        "kind": "stage.started",
                        "stage_id": run["stage_id"],
                        "label": stage.get("title", run["stage_id"]),
                        "actor": stage.get("agent", "specialist-agent"),
                        "state": "running",
                    }
                )
            if run.get("completed_at"):
                frames.append(
                    {
                        "frame_id": f"F-{run['stage_id']}-END",
                        "at": run["completed_at"],
                        "kind": f"stage.{run['state']}",
                        "stage_id": run["stage_id"],
                        "label": stage.get("title", run["stage_id"]),
                        "actor": stage.get("agent", "specialist-agent"),
                        "state": run["state"],
                    }
                )

        for event in snapshot.get("events", []):
            frames.append(
                {
                    "frame_id": event["event_id"],
                    "at": event["created_at"],
                    "kind": event["kind"],
                    "stage_id": event.get("stage_id"),
                    "label": event["kind"].replace(".", " ").title(),
                    "actor": event["actor"],
                    "state": "observed",
                }
            )

        frames.sort(key=lambda row: (row.get("at") or "", row["frame_id"]))
        for index, frame in enumerate(frames):
            frame["index"] = index

        return {
            "version": self.VERSION,
            "mission_id": mission_id,
            "status": mission["status"],
            "frame_count": len(frames),
            "frames": frames,
        }

    def evidence_workspace(self, mission_id: str) -> dict[str, Any]:
        snapshot = self.operations.snapshot(mission_id)
        mission = snapshot["mission"]
        stage_by_id = {s["stage_id"]: s for s in mission["plan"].get("stages", [])}
        items: list[dict[str, Any]] = []
        by_type: Counter[str] = Counter()
        by_stage: Counter[str] = Counter()

        for evidence in snapshot.get("evidence", []):
            stage = stage_by_id.get(evidence.get("stage_id") or "", {})
            metadata = evidence.get("metadata") or {}
            row = {
                **evidence,
                "stage_title": stage.get("title"),
                "agent": stage.get("agent"),
                "counter_evidence": bool(metadata.get("counter_evidence")),
                "entities": metadata.get("entities", []),
                "attack_techniques": metadata.get("attack_techniques", []),
            }
            items.append(row)
            by_type[evidence["evidence_type"]] += 1
            if evidence.get("stage_id"):
                by_stage[evidence["stage_id"]] += 1

        return {
            "version": self.VERSION,
            "mission_id": mission_id,
            "count": len(items),
            "items": items,
            "facets": {
                "types": dict(sorted(by_type.items())),
                "stages": dict(sorted(by_stage.items())),
                "counter_evidence": sum(1 for item in items if item["counter_evidence"]),
            },
        }

    def twin_projection(self, mission_id: str) -> dict[str, Any]:
        snapshot = self.operations.snapshot(mission_id)
        mission = snapshot["mission"]
        runs = {r["stage_id"]: r["state"] for r in mission.get("stage_runs", [])}
        stages = mission["plan"].get("stages", [])
        evidence = snapshot.get("evidence", [])
        evidence_by_stage: defaultdict[str, int] = defaultdict(int)
        for row in evidence:
            if row.get("stage_id"):
                evidence_by_stage[row["stage_id"]] += 1

        nodes: list[dict[str, Any]] = [
            {
                "node_id": "MISSION",
                "label": mission["mission_id"],
                "kind": "mission",
                "state": mission["status"],
                "evidence_count": len(evidence),
            }
        ]
        edges: list[dict[str, Any]] = []

        for stage in stages:
            sid = stage["stage_id"]
            nodes.append(
                {
                    "node_id": sid,
                    "label": stage["title"],
                    "kind": "stage",
                    "agent": stage["agent"],
                    "state": runs.get(sid, "waiting"),
                    "evidence_count": evidence_by_stage[sid],
                    "requires_scope": bool(stage.get("requires_scope")),
                }
            )
            if not stage.get("depends_on"):
                edges.append({"source": "MISSION", "target": sid, "kind": "starts"})
            for parent in stage.get("depends_on", []):
                edges.append({"source": parent, "target": sid, "kind": "depends-on"})

        return {
            "version": self.VERSION,
            "mission_id": mission_id,
            "nodes": nodes,
            "edges": edges,
            "active_path": [n["node_id"] for n in nodes if n.get("state") in {"running", "completed"}],
        }

    def multi_agent_review(self, mission_id: str) -> dict[str, Any]:
        snapshot = self.operations.snapshot(mission_id)
        mission = snapshot["mission"]
        supervisor = snapshot["supervisor"]
        runs = {r["stage_id"]: r for r in mission.get("stage_runs", [])}
        evidence = snapshot.get("evidence", [])
        stage_reviews = []

        for stage in mission["plan"].get("stages", []):
            sid = stage["stage_id"]
            run = runs.get(sid, {})
            linked = [e for e in evidence if e.get("stage_id") == sid]
            counter = sum(1 for e in linked if (e.get("metadata") or {}).get("counter_evidence") is True)
            support = len(linked) - counter
            stage_reviews.append(
                {
                    "stage_id": sid,
                    "agent": stage["agent"],
                    "state": run.get("state", "waiting"),
                    "supporting_evidence": support,
                    "counter_evidence": counter,
                    "assessment": (
                        "blocked" if run.get("state") == "failed"
                        else "supported" if support and not counter
                        else "contested" if counter
                        else "awaiting-evidence"
                    ),
                }
            )

        disagreements = [row for row in stage_reviews if row["assessment"] == "contested"]
        completed = sum(1 for row in stage_reviews if row["state"] == "completed")
        coverage = completed / len(stage_reviews) if stage_reviews else 0.0
        quality = max(
            0.0,
            min(
                1.0,
                (supervisor.get("confidence", 0.0) * 0.55)
                + (coverage * 0.35)
                + (0.10 if evidence else 0.0)
                - min(len(disagreements), 5) * 0.04,
            ),
        )

        return {
            "version": self.VERSION,
            "mission_id": mission_id,
            "supervisor": supervisor,
            "stage_reviews": stage_reviews,
            "disagreements": disagreements,
            "quality_score": round(quality, 4),
            "recommended_action": (
                "resolve-blockers" if supervisor.get("blockers", 0)
                else "review-counter-evidence" if disagreements
                else "continue-collection" if coverage < 0.75
                else "ready-for-synthesis"
            ),
        }

    def related_missions(self, mission_id: str, limit: int = 8) -> dict[str, Any]:
        current = self.operations.phase6.get_mission(mission_id)
        current_tokens = self._tokens(current["objective"])
        current_agents = set(current["plan"].get("agents", []))
        current_tools = {
            stage.get("tool_id")
            for stage in current["plan"].get("stages", [])
            if stage.get("tool_id")
        }
        candidates = []

        for row in self.operations.phase6.list_missions(limit=500):
            if row["mission_id"] == mission_id:
                continue
            try:
                other = self.operations.phase6.get_mission(row["mission_id"])
            except KeyError:
                continue
            objective_overlap = self._score_overlap(current_tokens, self._tokens(other["objective"]))
            other_agents = set(other["plan"].get("agents", []))
            other_tools = {
                stage.get("tool_id")
                for stage in other["plan"].get("stages", [])
                if stage.get("tool_id")
            }
            agent_overlap = self._score_overlap(current_agents, other_agents)
            tool_overlap = self._score_overlap(current_tools, other_tools)
            same_case = bool(current.get("case_id") and current.get("case_id") == other.get("case_id"))
            score = min(1.0, objective_overlap * 0.55 + agent_overlap * 0.20 + tool_overlap * 0.20 + (0.05 if same_case else 0.0))
            if score <= 0:
                continue
            reasons = []
            if objective_overlap: reasons.append("objective-overlap")
            if agent_overlap: reasons.append("shared-agents")
            if tool_overlap: reasons.append("shared-capabilities")
            if same_case: reasons.append("same-case")
            candidates.append(
                {
                    "mission_id": other["mission_id"],
                    "case_id": other.get("case_id"),
                    "objective": other["objective"],
                    "status": other["status"],
                    "similarity": round(score, 4),
                    "reasons": reasons,
                }
            )

        candidates.sort(key=lambda item: (-item["similarity"], item["mission_id"]))
        memories = self.operations.phase6.memory(case_id=current.get("case_id"), limit=20) if current.get("case_id") else self.operations.phase6.memory(limit=20)
        return {
            "version": self.VERSION,
            "mission_id": mission_id,
            "related": candidates[: max(1, min(limit, 25))],
            "lessons": memories,
        }

    def workspace(self, mission_id: str) -> dict[str, Any]:
        snapshot = self.operations.snapshot(mission_id)
        return {
            "version": self.VERSION,
            "mission_id": mission_id,
            "snapshot": snapshot,
            "replay": self.replay(mission_id),
            "evidence_workspace": self.evidence_workspace(mission_id),
            "twin": self.twin_projection(mission_id),
            "review": self.multi_agent_review(mission_id),
            "memory": self.related_missions(mission_id),
        }
