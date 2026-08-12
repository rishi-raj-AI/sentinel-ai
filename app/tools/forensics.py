from __future__ import annotations

from pathlib import Path

from app.forensics.case_manager import CaseManager
from app.forensics.correlation import CorrelationEngine
from app.forensics.evidence import EvidenceManager
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.event_import import import_jsonl_events, timeline_summary
from app.forensics.investigation import InvestigationEngine
from app.forensics.macos_logs import MacOSLogAdapter
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.pcap import TsharkAdapter
from app.forensics.sample_pcap import create_sample_pcap as generate_sample_pcap
from app.forensics.volatility import VolatilityAdapter


def create_case(title: str, description: str = ""):
    return CaseManager().create_case(title=title, description=description)


def register_evidence(case_id: str, path: str):
    return EvidenceManager().register(case_id=case_id, source_path=path, copy=True)


def verify_evidence(case_id: str, evidence_id: str | None = None):
    return EvidenceManager().verify(case_id=case_id, evidence_id=evidence_id)


def show_case(case_id: str):
    return CaseManager().load_case(case_id)


def import_events(case_id: str, path: str, source_name: str = "jsonl", evidence_id: str | None = None):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return import_jsonl_events(case_dir, path, source_name=source_name, evidence_id=evidence_id)


def show_timeline(case_id: str):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return timeline_summary(case_dir)


def correlate_case(case_id: str, window_seconds: int = 300):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return CorrelationEngine(case_dir).analyze(window_seconds=window_seconds)


def evidence_graph(case_id: str, max_nodes: int = 1000, max_edges: int = 2000):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return EvidenceGraphEngine(case_dir).build(max_nodes=max_nodes, max_edges=max_edges)


def _is_packet_level_network_finding(finding: dict) -> bool:
    events = finding.get("events") or []
    if not events:
        return False
    return all(
        event.get("source") == "tshark" and event.get("event_type") == "network"
        for event in events
    )


def investigate_case(case_id: str, window_seconds: int = 120, max_findings: int = 25):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)

    result = InvestigationEngine(case_dir).analyze(
        window_seconds=window_seconds,
        max_findings=max_findings,
    )
    network = NetworkIntelligenceEngine(case_dir).analyze(max_flows=max_findings)

    result["findings"] = [
        finding
        for finding in result.get("findings", [])
        if not _is_packet_level_network_finding(finding)
    ]

    aggregated_findings: list[dict] = []
    for flow in network["findings"]["public_destination_flows"]:
        aggregated_findings.append(
            {
                "title": "Public destination network flow",
                "severity": "medium",
                "confidence": "medium",
                "reason": f"{flow.get('src')}:{flow.get('src_port')} -> {flow.get('dst')}:{flow.get('dst_port')}",
                "flow": flow,
            }
        )
    for flow in network["findings"]["unusual_destination_ports"]:
        aggregated_findings.append(
            {
                "title": "Unusual destination port",
                "severity": "medium",
                "confidence": "medium",
                "reason": f"Network flow used destination port {flow.get('dst_port')}",
                "flow": flow,
            }
        )

    result["network_summary"] = {
        "network_event_count": network["network_event_count"],
        "network_events_ignored": network["network_events_ignored"],
        "flow_count": network["flow_count"],
        "dns_queries": network["dns_queries"],
        "http_hosts": network["http_hosts"],
        "tls_sni": network["tls_sni"],
        "source_scopes": network["source_scopes"],
        "destination_scopes": network["destination_scopes"],
    }
    result["network_findings"] = aggregated_findings[:max_findings]

    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for finding in result["findings"]:
        severity = str(finding.get("severity", "low"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    result["summary"]["finding_count"] = len(result["findings"])
    result["summary"]["severity_counts"] = severity_counts
    result["summary"]["network_finding_count"] = len(result["network_findings"])

    if severity_counts.get("high", 0):
        result["summary"]["overall_assessment"] = "high-priority activity requires review"
    elif severity_counts.get("medium", 0) or result["network_findings"]:
        result["summary"]["overall_assessment"] = "some activity warrants investigator review"
    else:
        result["summary"]["overall_assessment"] = "no high-priority findings"

    return result


def network_intelligence(case_id: str, max_flows: int = 100):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return NetworkIntelligenceEngine(case_dir).analyze(max_flows=max_flows)


def collect_macos_logs(
    case_id: str,
    last: str = "5m",
    predicate: str | None = None,
    max_events: int = 1000,
):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return MacOSLogAdapter(case_dir).collect(
        last=last,
        predicate=predicate,
        max_events=max_events,
    )


def volatility_status():
    return VolatilityAdapter.status()


def tshark_status():
    return TsharkAdapter.status()


def create_sample_pcap(path: str = "workspace/sample.pcap"):
    return generate_sample_pcap(path)


def _resolve_case_evidence(case_id: str, evidence_id: str) -> dict:
    record = CaseManager().load_case(case_id)
    for item in record.get("evidence", []):
        if item.get("evidence_id") == evidence_id:
            return item
    raise ValueError(f"Evidence not found in {case_id}: {evidence_id}")


def run_volatility(
    case_id: str,
    image_path: str,
    plugin: str,
    evidence_id: str | None = None,
):
    case_dir = CaseManager().root / case_id
    CaseManager().load_case(case_id)
    return VolatilityAdapter(case_dir).run(
        image_path=image_path,
        plugin=plugin,
        evidence_id=evidence_id,
    )


def run_volatility_evidence(case_id: str, evidence_id: str, plugin: str):
    verification = EvidenceManager().verify(case_id=case_id, evidence_id=evidence_id)
    if not verification.get("all_match") or not verification.get("chain_of_custody_valid"):
        raise RuntimeError(f"Evidence integrity verification failed for {case_id}/{evidence_id}")

    item = _resolve_case_evidence(case_id, evidence_id)
    stored_path = Path(item["stored_path"]).resolve()
    if not stored_path.is_file():
        raise FileNotFoundError(f"Stored evidence file not found: {stored_path}")

    case_dir = CaseManager().root / case_id
    result = VolatilityAdapter(case_dir).run(
        image_path=str(stored_path),
        plugin=plugin,
        evidence_id=evidence_id,
    )
    result["case_id"] = case_id
    result["evidence_id"] = evidence_id
    result["evidence_sha256_verified"] = True
    result["chain_of_custody_valid"] = True
    return result


def analyze_pcap_evidence(case_id: str, evidence_id: str, max_packets: int = 5000):
    verification = EvidenceManager().verify(case_id=case_id, evidence_id=evidence_id)
    if not verification.get("all_match") or not verification.get("chain_of_custody_valid"):
        raise RuntimeError(f"Evidence integrity verification failed for {case_id}/{evidence_id}")

    item = _resolve_case_evidence(case_id, evidence_id)
    stored_path = Path(item["stored_path"]).resolve()
    if not stored_path.is_file():
        raise FileNotFoundError(f"Stored evidence file not found: {stored_path}")

    case_dir = CaseManager().root / case_id
    result = TsharkAdapter(case_dir).analyze(
        pcap_path=str(stored_path),
        evidence_id=evidence_id,
        max_packets=max_packets,
    )
    result["case_id"] = case_id
    result["evidence_id"] = evidence_id
    result["evidence_sha256_verified"] = True
    result["chain_of_custody_valid"] = True
    return result
