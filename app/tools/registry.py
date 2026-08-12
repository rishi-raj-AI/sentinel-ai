from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable

import psutil

from app.tools.copilot import copilot_ask, copilot_status
from app.tools.evtx import create_sample_evtx, evtx_analyze_evidence, evtx_status
from app.tools.forensics import analyze_pcap_evidence, attack_chain, attack_mapping, collect_macos_logs, correlate_case, create_case, create_sample_pcap, evidence_graph, graph_neighbors, graph_trace, import_events, investigate_case, network_intelligence, register_evidence, run_volatility, run_volatility_evidence, show_case, show_timeline, tshark_status, verify_evidence, volatility_status, yara_scan_evidence, yara_status
from app.tools.memory import forget, list_memories, recall, remember
from app.tools.reasoning import case_brief, threat_intel_inventory
from app.tools.reporting import export_case_report, verify_case_report
from app.tools.sigma import sigma_analyze

ToolFunction = Callable[..., Any]


def list_directory(path: str = ".") -> list[str]:
    target = Path(path).expanduser().resolve()
    return sorted(item.name for item in target.iterdir())


def read_text_file(path: str, max_bytes: int = 1_000_000) -> str:
    target = Path(path).expanduser().resolve()
    if target.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds read limit of {max_bytes} bytes")
    return target.read_text(encoding="utf-8")


def write_text_file(path: str, content: str, overwrite: bool = False) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    if target.exists() and not overwrite:
        raise FileExistsError(f"File already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return {"path": str(target), "bytes_written": len(content.encode("utf-8"))}


def create_directory(path: str) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    return {"path": str(target), "created": True}


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    target = Path(path).expanduser().resolve()
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def disk_usage(path: str = "/") -> dict[str, int | float]:
    usage = psutil.disk_usage(str(Path(path).expanduser()))
    return {"total": usage.total, "used": usage.used, "free": usage.free, "percent": usage.percent}


def system_info() -> dict[str, Any]:
    return {"cpu_percent": psutil.cpu_percent(interval=0.1), "memory": psutil.virtual_memory()._asdict(), "boot_time": psutil.boot_time()}


TOOLS: dict[str, ToolFunction] = {
    "filesystem.list_directory": list_directory,
    "filesystem.read_text_file": read_text_file,
    "filesystem.write_text_file": write_text_file,
    "filesystem.create_directory": create_directory,
    "forensic.sha256_file": sha256_file,
    "forensic.create_case": create_case,
    "forensic.register_evidence": register_evidence,
    "forensic.verify_evidence": verify_evidence,
    "forensic.show_case": show_case,
    "forensic.import_events": import_events,
    "forensic.show_timeline": show_timeline,
    "forensic.correlate_case": correlate_case,
    "forensic.investigate_case": investigate_case,
    "forensic.network_intelligence": network_intelligence,
    "forensic.evidence_graph": evidence_graph,
    "forensic.graph_neighbors": graph_neighbors,
    "forensic.graph_trace": graph_trace,
    "forensic.attack_mapping": attack_mapping,
    "forensic.attack_chain": attack_chain,
    "forensic.yara_status": yara_status,
    "forensic.yara_scan_evidence": yara_scan_evidence,
    "forensic.evtx_status": evtx_status,
    "forensic.create_sample_evtx": create_sample_evtx,
    "forensic.evtx_analyze_evidence": evtx_analyze_evidence,
    "forensic.sigma_analyze": sigma_analyze,
    "forensic.case_brief": case_brief,
    "forensic.threat_intel_inventory": threat_intel_inventory,
    "forensic.export_case_report": export_case_report,
    "forensic.verify_case_report": verify_case_report,
    "forensic.copilot_status": copilot_status,
    "forensic.copilot_ask": copilot_ask,
    "forensic.collect_macos_logs": collect_macos_logs,
    "forensic.volatility_status": volatility_status,
    "forensic.run_volatility": run_volatility,
    "forensic.run_volatility_evidence": run_volatility_evidence,
    "forensic.tshark_status": tshark_status,
    "forensic.create_sample_pcap": create_sample_pcap,
    "forensic.analyze_pcap_evidence": analyze_pcap_evidence,
    "system.disk_usage": disk_usage,
    "system.info": system_info,
    "memory.remember": remember,
    "memory.recall": recall,
    "memory.forget": forget,
    "memory.list": list_memories,
}


def get_tool(name: str) -> ToolFunction:
    try:
        return TOOLS[name]
    except KeyError as exc:
        raise ValueError(f"Unknown or unregistered tool: {name}") from exc