from __future__ import annotations

from app.models import CommandPlan, ToolCall


def plan_command(command: str) -> CommandPlan:
    """Phase 1 deterministic planner.

    This intentionally avoids an LLM dependency until the tool/execution boundary is
    proven. A model-backed planner can later emit the same CommandPlan schema.
    """
    text = command.strip()
    lower = text.lower()

    if lower in {"system info", "show system info", "what's running on my mac"}:
        return CommandPlan(
            intent="inspect_system",
            steps=[ToolCall(tool="system.info")],
        )

    if lower.startswith("disk usage"):
        path = text[len("disk usage") :].strip() or "/"
        return CommandPlan(
            intent="inspect_disk_usage",
            steps=[ToolCall(tool="system.disk_usage", arguments={"path": path})],
        )

    if lower.startswith("list "):
        path = text[5:].strip() or "."
        return CommandPlan(
            intent="list_directory",
            steps=[ToolCall(tool="filesystem.list_directory", arguments={"path": path})],
        )

    if lower.startswith("read "):
        path = text[5:].strip()
        return CommandPlan(
            intent="read_text_file",
            steps=[ToolCall(tool="filesystem.read_text_file", arguments={"path": path})],
        )

    if lower.startswith("sha256 "):
        path = text[7:].strip()
        return CommandPlan(
            intent="hash_file",
            steps=[ToolCall(tool="forensic.sha256_file", arguments={"path": path})],
        )

    return CommandPlan(intent="unknown", requires_action=False, steps=[])
