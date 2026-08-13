from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass(slots=True)
class SkillSpec:
    skill_id: str
    name: str
    domain: str
    purpose: str
    inputs: list[str]
    outputs: list[str]
    adapters: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=lambda: ["case.read"])
    read_only: bool = True
    requires_scope: bool = False
    requires_human_approval: bool = False
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DecisionPlan:
    objective: str
    selected_skills: list[dict[str, Any]]
    rejected_skills: list[dict[str, Any]]
    required_permissions: list[str]
    requires_human_approval: bool
    rationale: list[str]


class SkillRegistry:
    VERSION = "X1.0"

    def __init__(self, path: str | Path = "config/cyber_skills.json") -> None:
        self.path = Path(path)
        self._skills: dict[str, SkillSpec] = {}
        self._install_defaults()
        self._load_user_skills()

    def _install_defaults(self) -> None:
        defaults = [
            SkillSpec("dfir.timeline", "Timeline Analysis", "dfir", "Analyze normalized forensic timelines", ["case"], ["timeline_findings"], ["sentinel.timeline"], tags=["timeline", "forensics"]),
            SkillSpec("dfir.memory", "Memory Analysis", "dfir", "Analyze already-acquired memory artifacts", ["memory_image"], ["memory_findings"], ["volatility3"], tags=["memory"]),
            SkillSpec("detection.sigma", "Sigma Analysis", "detection", "Evaluate detection rules against normalized telemetry", ["case"], ["detections"], ["sentinel.sigma"], tags=["sigma", "detection"]),
            SkillSpec("detection.yara", "YARA Analysis", "malware", "Evaluate YARA matches and sample metadata", ["evidence"], ["matches"], ["sentinel.yara"], tags=["yara", "malware"]),
            SkillSpec("network.analysis", "Network Intelligence", "network", "Analyze normalized network flows and relationships", ["network_events"], ["network_findings"], ["sentinel.network"], tags=["network", "flow", "dns"]),
            SkillSpec("graph.reason", "Security Graph Reasoning", "reasoning", "Traverse evidence and security-knowledge relationships", ["graph"], ["paths", "correlations"], ["sentinel.graph"], tags=["graph", "correlation"]),
            SkillSpec("intel.lookup", "Cyber Intelligence Lookup", "threat-intel", "Query locally ingested cyber intelligence", ["query"], ["intel_matches"], ["sentinel.intel"], tags=["cve", "cwe", "attack", "intel"]),
            SkillSpec("scope.inventory", "Scoped Asset Inventory", "assessment", "Normalize assets registered in an approved engagement scope", ["scope"], ["assets"], ["sentinel.scope"], permissions=["case.read", "workspace.write"], requires_scope=True, tags=["asset", "scope", "inventory"]),
            SkillSpec("report.finding", "Finding Workflow", "reporting", "Create evidence-linked security findings and remediation records", ["finding"], ["finding_record"], ["sentinel.findings"], permissions=["workspace.write"], tags=["report", "cvss", "cwe"]),
        ]
        self._skills.update({s.skill_id: s for s in defaults})

    def _load_user_skills(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for row in data if isinstance(data, list) else []:
            try:
                spec = SkillSpec(**row)
            except (TypeError, ValueError):
                continue
            self._skills[spec.skill_id] = spec

    def register(self, spec: SkillSpec) -> None:
        self._skills[spec.skill_id] = spec

    def list(self, *, domain: str | None = None) -> list[dict[str, Any]]:
        rows = [asdict(x) for x in self._skills.values() if domain is None or x.domain == domain]
        return sorted(rows, key=lambda x: (x["domain"], x["skill_id"]))

    def get(self, skill_id: str) -> SkillSpec:
        if skill_id not in self._skills:
            raise KeyError(skill_id)
        return self._skills[skill_id]

    def search(self, text: str, *, limit: int = 12) -> list[SkillSpec]:
        terms = {x.casefold() for x in text.replace("/", " ").replace("-", " ").split() if len(x) > 2}
        scored: list[tuple[int, SkillSpec]] = []
        for skill in self._skills.values():
            blob = " ".join([skill.skill_id, skill.name, skill.domain, skill.purpose, *skill.tags, *skill.adapters]).casefold()
            score = sum(1 for term in terms if term in blob)
            if score:
                scored.append((score, skill))
        scored.sort(key=lambda x: (x[0], x[1].skill_id), reverse=True)
        return [skill for _, skill in scored[:limit]]


class CyberBrain:
    """Non-executing capability planner with explicit prerequisite checks."""

    def __init__(self, registry: SkillRegistry | None = None) -> None:
        self.registry = registry or SkillRegistry()

    def plan(self, objective: str, *, available_permissions: Iterable[str] = ("case.read",), scoped_engagement: bool = False, max_skills: int = 8) -> DecisionPlan:
        permissions = set(available_permissions)
        selected: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        rationale: list[str] = []
        for skill in self.registry.search(objective, limit=max_skills * 3):
            missing = sorted(set(skill.permissions) - permissions)
            reason = None
            if missing:
                reason = f"missing permissions: {', '.join(missing)}"
            elif skill.requires_scope and not scoped_engagement:
                reason = "requires a registered engagement scope"
            row = {"skill_id": skill.skill_id, "name": skill.name, "domain": skill.domain}
            if reason:
                rejected.append({**row, "reason": reason})
            elif len(selected) < max_skills:
                selected.append({**row, "read_only": skill.read_only, "adapters": skill.adapters, "approval": skill.requires_human_approval})
                rationale.append(f"Selected {skill.skill_id}: prerequisites satisfied and objective terms matched.")
        required = sorted({p for row in selected for p in self.registry.get(row["skill_id"]).permissions})
        approval = any(bool(row.get("approval")) for row in selected)
        return DecisionPlan(objective, selected, rejected, required, approval, rationale)
