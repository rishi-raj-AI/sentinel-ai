from __future__ import annotations

from app.brain.planner import plan_command as base_plan_command
from app.models import CommandPlan, ToolCall


def plan_command(command: str) -> CommandPlan:
    text = command.strip()
    lower = text.lower()

    if lower.startswith("sigma analyze ") or lower.startswith("sigma scan "):
        prefix = "sigma analyze " if lower.startswith("sigma analyze ") else "sigma scan "
        parts = text[len(prefix):].strip().split(maxsplit=2)
        if len(parts) >= 2:
            arguments: dict[str, object] = {"case_id": parts[0], "rule_path": parts[1]}
            if len(parts) == 3 and parts[2].isdigit():
                arguments["max_detections"] = int(parts[2])
            return CommandPlan(
                intent="sigma_analyze",
                steps=[ToolCall(tool="forensic.sigma_analyze", arguments=arguments)],
            )

    return base_plan_command(command)
