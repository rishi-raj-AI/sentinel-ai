from __future__ import annotations

from app.models import CommandPlan, ToolCall


def plan_command(command: str) -> CommandPlan:
    text = command.strip()
    lower = text.lower()

    if lower in {"system info", "show system info", "what's running on my mac"}:
        return CommandPlan(intent="inspect_system", steps=[ToolCall(tool="system.info")])
    if lower.startswith("disk usage"):
        path = text[len("disk usage") :].strip() or "/"
        return CommandPlan(intent="inspect_disk_usage", steps=[ToolCall(tool="system.disk_usage", arguments={"path": path})])
    if lower.startswith("list "):
        return CommandPlan(intent="list_directory", steps=[ToolCall(tool="filesystem.list_directory", arguments={"path": text[5:].strip() or "."})])
    if lower.startswith("read "):
        return CommandPlan(intent="read_text_file", steps=[ToolCall(tool="filesystem.read_text_file", arguments={"path": text[5:].strip()})])
    if lower.startswith("sha256 "):
        return CommandPlan(intent="hash_file", steps=[ToolCall(tool="forensic.sha256_file", arguments={"path": text[7:].strip()})])
    if lower.startswith("mkdir "):
        return CommandPlan(intent="create_directory", steps=[ToolCall(tool="filesystem.create_directory", arguments={"path": text[6:].strip()})])
    if lower.startswith("remember ") and "=" in text:
        key, value = text[len("remember ") :].split("=", 1)
        return CommandPlan(intent="remember", steps=[ToolCall(tool="memory.remember", arguments={"key": key.strip(), "value": value.strip()})])
    if lower.startswith("recall "):
        return CommandPlan(intent="recall", steps=[ToolCall(tool="memory.recall", arguments={"key": text[len("recall ") :].strip()})])
    if lower in {"memories", "list memories"}:
        return CommandPlan(intent="list_memories", steps=[ToolCall(tool="memory.list")])
    if lower.startswith("forget "):
        return CommandPlan(intent="forget", steps=[ToolCall(tool="memory.forget", arguments={"key": text[len("forget ") :].strip()})])
    if lower.startswith("create case "):
        return CommandPlan(intent="create_forensic_case", steps=[ToolCall(tool="forensic.create_case", arguments={"title": text[len("create case ") :].strip()})])
    if lower.startswith("show case "):
        return CommandPlan(intent="show_forensic_case", steps=[ToolCall(tool="forensic.show_case", arguments={"case_id": text[len("show case ") :].strip()})])
    if lower.startswith("register evidence "):
        parts = text[len("register evidence ") :].strip().split(maxsplit=1)
        if len(parts) == 2:
            return CommandPlan(intent="register_evidence", steps=[ToolCall(tool="forensic.register_evidence", arguments={"case_id": parts[0], "path": parts[1]})])
    if lower.startswith("verify evidence "):
        parts = text[len("verify evidence ") :].strip().split()
        if len(parts) == 1:
            return CommandPlan(intent="verify_case_evidence", steps=[ToolCall(tool="forensic.verify_evidence", arguments={"case_id": parts[0]})])
        if len(parts) >= 2:
            return CommandPlan(intent="verify_single_evidence", steps=[ToolCall(tool="forensic.verify_evidence", arguments={"case_id": parts[0], "evidence_id": parts[1]})])
    if lower.startswith("import events "):
        parts = text[len("import events ") :].strip().split(maxsplit=2)
        if len(parts) >= 2:
            return CommandPlan(intent="import_forensic_events", steps=[ToolCall(tool="forensic.import_events", arguments={"case_id": parts[0], "path": parts[1], "source_name": parts[2] if len(parts) == 3 else "jsonl"})])
    if lower.startswith("timeline "):
        return CommandPlan(intent="show_forensic_timeline", steps=[ToolCall(tool="forensic.show_timeline", arguments={"case_id": text[len("timeline ") :].strip()})])
    if lower.startswith("correlate ") or lower.startswith("analyze case "):
        prefix = "correlate " if lower.startswith("correlate ") else "analyze case "
        parts = text[len(prefix) :].strip().split()
        if parts:
            arguments = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["window_seconds"] = int(parts[1])
            return CommandPlan(intent="correlate_forensic_case", steps=[ToolCall(tool="forensic.correlate_case", arguments=arguments)])

    return CommandPlan(intent="unknown", requires_action=False, steps=[])
