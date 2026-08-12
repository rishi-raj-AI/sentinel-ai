from __future__ import annotations

from app.models import CommandPlan, ToolCall


def plan_command(command: str) -> CommandPlan:
    """Deterministic planner for the first Sentinel milestones.

    A model-backed planner can later emit the same CommandPlan schema without
    changing the execution boundary.
    """
    text = command.strip()
    lower = text.lower()

    if lower in {"system info", "show system info", "what's running on my mac"}:
        return CommandPlan(intent="inspect_system", steps=[ToolCall(tool="system.info")])

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

    if lower.startswith("mkdir "):
        path = text[6:].strip()
        return CommandPlan(
            intent="create_directory",
            steps=[ToolCall(tool="filesystem.create_directory", arguments={"path": path})],
        )

    if lower.startswith("remember ") and "=" in text:
        payload = text[len("remember ") :]
        key, value = payload.split("=", 1)
        return CommandPlan(
            intent="remember",
            steps=[
                ToolCall(
                    tool="memory.remember",
                    arguments={"key": key.strip(), "value": value.strip()},
                )
            ],
        )

    if lower.startswith("recall "):
        key = text[len("recall ") :].strip()
        return CommandPlan(
            intent="recall",
            steps=[ToolCall(tool="memory.recall", arguments={"key": key})],
        )

    if lower == "memories" or lower == "list memories":
        return CommandPlan(intent="list_memories", steps=[ToolCall(tool="memory.list")])

    if lower.startswith("forget "):
        key = text[len("forget ") :].strip()
        return CommandPlan(
            intent="forget",
            steps=[ToolCall(tool="memory.forget", arguments={"key": key})],
        )

    return CommandPlan(intent="unknown", requires_action=False, steps=[])
