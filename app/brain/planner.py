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
            steps=[ToolCall(tool="memory.remember", arguments={"key": key.strip(), "value": value.strip()})],
        )

    if lower.startswith("recall "):
        key = text[len("recall ") :].strip()
        return CommandPlan(intent="recall", steps=[ToolCall(tool="memory.recall", arguments={"key": key})])

    if lower == "memories" or lower == "list memories":
        return CommandPlan(intent="list_memories", steps=[ToolCall(tool="memory.list")])

    if lower.startswith("forget "):
        key = text[len("forget ") :].strip()
        return CommandPlan(intent="forget", steps=[ToolCall(tool="memory.forget", arguments={"key": key})])

    if lower.startswith("create case "):
        title = text[len("create case ") :].strip()
        return CommandPlan(
            intent="create_forensic_case",
            steps=[ToolCall(tool="forensic.create_case", arguments={"title": title})],
        )

    if lower.startswith("show case "):
        case_id = text[len("show case ") :].strip()
        return CommandPlan(
            intent="show_forensic_case",
            steps=[ToolCall(tool="forensic.show_case", arguments={"case_id": case_id})],
        )

    if lower.startswith("register evidence "):
        payload = text[len("register evidence ") :].strip()
        parts = payload.split(maxsplit=1)
        if len(parts) == 2:
            case_id, path = parts
            return CommandPlan(
                intent="register_evidence",
                steps=[ToolCall(tool="forensic.register_evidence", arguments={"case_id": case_id, "path": path})],
            )

    if lower.startswith("verify evidence "):
        payload = text[len("verify evidence ") :].strip()
        parts = payload.split()
        if len(parts) == 1:
            return CommandPlan(
                intent="verify_case_evidence",
                steps=[ToolCall(tool="forensic.verify_evidence", arguments={"case_id": parts[0]})],
            )
        if len(parts) >= 2:
            return CommandPlan(
                intent="verify_single_evidence",
                steps=[ToolCall(tool="forensic.verify_evidence", arguments={"case_id": parts[0], "evidence_id": parts[1]})],
            )

    if lower.startswith("import events "):
        payload = text[len("import events ") :].strip()
        parts = payload.split(maxsplit=2)
        if len(parts) >= 2:
            case_id, path = parts[0], parts[1]
            source_name = parts[2] if len(parts) == 3 else "jsonl"
            return CommandPlan(
                intent="import_forensic_events",
                steps=[ToolCall(tool="forensic.import_events", arguments={"case_id": case_id, "path": path, "source_name": source_name})],
            )

    if lower.startswith("timeline "):
        case_id = text[len("timeline ") :].strip()
        return CommandPlan(
            intent="show_forensic_timeline",
            steps=[ToolCall(tool="forensic.show_timeline", arguments={"case_id": case_id})],
        )

    return CommandPlan(intent="unknown", requires_action=False, steps=[])
