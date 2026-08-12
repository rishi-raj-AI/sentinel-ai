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
            return CommandPlan(intent="sigma_analyze", steps=[ToolCall(tool="forensic.sigma_analyze", arguments=arguments)])

    if lower.startswith("case brief ") or lower.startswith("investigation brief "):
        prefix = "case brief " if lower.startswith("case brief ") else "investigation brief "
        parts = text[len(prefix):].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["max_items"] = int(parts[1])
            return CommandPlan(intent="case_brief", steps=[ToolCall(tool="forensic.case_brief", arguments=arguments)])

    if lower.startswith("threat intel ") or lower.startswith("ioc inventory "):
        prefix = "threat intel " if lower.startswith("threat intel ") else "ioc inventory "
        parts = text[len(prefix):].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["max_items"] = int(parts[1])
            return CommandPlan(intent="threat_intel_inventory", steps=[ToolCall(tool="forensic.threat_intel_inventory", arguments=arguments)])

    if lower.startswith("export report ") or lower.startswith("report export "):
        prefix = "export report " if lower.startswith("export report ") else "report export "
        parts = text[len(prefix):].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2:
                arguments["output_format"] = parts[1]
            if len(parts) >= 3 and parts[2].isdigit():
                arguments["max_items"] = int(parts[2])
            if len(parts) >= 4:
                arguments["report_name"] = parts[3]
            return CommandPlan(intent="export_case_report", steps=[ToolCall(tool="forensic.export_case_report", arguments=arguments)])

    if lower.startswith("verify report ") or lower.startswith("report verify "):
        prefix = "verify report " if lower.startswith("verify report ") else "report verify "
        parts = text[len(prefix):].strip().split(maxsplit=1)
        if len(parts) == 2:
            return CommandPlan(
                intent="verify_case_report",
                steps=[ToolCall(tool="forensic.verify_case_report", arguments={"case_id": parts[0], "report_name": parts[1]})],
            )

    return base_plan_command(command)
