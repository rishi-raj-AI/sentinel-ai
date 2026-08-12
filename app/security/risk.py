from __future__ import annotations

from app.models import RiskLevel, ToolCall


TOOL_RISK: dict[str, RiskLevel] = {
    "filesystem.list_directory": RiskLevel.READ,
    "filesystem.read_text_file": RiskLevel.READ,
    "forensic.sha256_file": RiskLevel.READ,
    "system.disk_usage": RiskLevel.READ,
    "system.info": RiskLevel.READ,
}


def classify_tool_call(call: ToolCall) -> RiskLevel:
    return TOOL_RISK.get(call.tool, RiskLevel.SYSTEM)


def requires_confirmation(risk: RiskLevel) -> bool:
    return risk >= RiskLevel.MODIFICATION
