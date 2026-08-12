from __future__ import annotations

from app.models import RiskLevel, ToolCall


TOOL_RISK: dict[str, RiskLevel] = {
    "filesystem.list_directory": RiskLevel.READ,
    "filesystem.read_text_file": RiskLevel.READ,
    "filesystem.write_text_file": RiskLevel.MODIFICATION,
    "filesystem.create_directory": RiskLevel.MODIFICATION,
    "forensic.sha256_file": RiskLevel.READ,
    "forensic.create_case": RiskLevel.MODIFICATION,
    "forensic.register_evidence": RiskLevel.MODIFICATION,
    "forensic.verify_evidence": RiskLevel.READ,
    "forensic.show_case": RiskLevel.READ,
    "forensic.import_events": RiskLevel.MODIFICATION,
    "forensic.show_timeline": RiskLevel.READ,
    "forensic.correlate_case": RiskLevel.READ,
    "system.disk_usage": RiskLevel.READ,
    "system.info": RiskLevel.READ,
    "memory.remember": RiskLevel.MODIFICATION,
    "memory.recall": RiskLevel.READ,
    "memory.forget": RiskLevel.MODIFICATION,
    "memory.list": RiskLevel.READ,
}


def classify_tool_call(call: ToolCall) -> RiskLevel:
    return TOOL_RISK.get(call.tool, RiskLevel.SYSTEM)


def requires_confirmation(risk: RiskLevel) -> bool:
    return risk >= RiskLevel.MODIFICATION
