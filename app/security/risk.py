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
    "forensic.investigate_case": RiskLevel.READ,
    "forensic.network_intelligence": RiskLevel.READ,
    "forensic.evidence_graph": RiskLevel.READ,
    "forensic.graph_neighbors": RiskLevel.READ,
    "forensic.graph_trace": RiskLevel.READ,
    "forensic.attack_mapping": RiskLevel.READ,
    "forensic.attack_chain": RiskLevel.READ,
    "forensic.yara_status": RiskLevel.READ,
    "forensic.yara_scan_evidence": RiskLevel.MODIFICATION,
    "forensic.evtx_status": RiskLevel.READ,
    "forensic.create_sample_evtx": RiskLevel.MODIFICATION,
    "forensic.evtx_analyze_evidence": RiskLevel.MODIFICATION,
    "forensic.sigma_analyze": RiskLevel.READ,
    "forensic.case_brief": RiskLevel.READ,
    "forensic.threat_intel_inventory": RiskLevel.READ,
    "forensic.export_case_report": RiskLevel.MODIFICATION,
    "forensic.verify_case_report": RiskLevel.READ,
    "forensic.collect_macos_logs": RiskLevel.MODIFICATION,
    "forensic.volatility_status": RiskLevel.READ,
    "forensic.run_volatility": RiskLevel.MODIFICATION,
    "forensic.run_volatility_evidence": RiskLevel.MODIFICATION,
    "forensic.tshark_status": RiskLevel.READ,
    "forensic.create_sample_pcap": RiskLevel.MODIFICATION,
    "forensic.analyze_pcap_evidence": RiskLevel.MODIFICATION,
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
