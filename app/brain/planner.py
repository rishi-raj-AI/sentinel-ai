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
    if lower.startswith("investigate ") or lower.startswith("investigation "):
        prefix = "investigate " if lower.startswith("investigate ") else "investigation "
        parts = text[len(prefix) :].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["window_seconds"] = int(parts[1])
            if len(parts) >= 3 and parts[2].isdigit():
                arguments["max_findings"] = int(parts[2])
            return CommandPlan(intent="investigate_forensic_case", steps=[ToolCall(tool="forensic.investigate_case", arguments=arguments)])
    if lower.startswith("network intelligence ") or lower.startswith("network summary "):
        prefix = "network intelligence " if lower.startswith("network intelligence ") else "network summary "
        parts = text[len(prefix) :].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["max_flows"] = int(parts[1])
            return CommandPlan(intent="network_intelligence", steps=[ToolCall(tool="forensic.network_intelligence", arguments=arguments)])
    if lower.startswith("evidence graph ") or lower.startswith("graph case "):
        prefix = "evidence graph " if lower.startswith("evidence graph ") else "graph case "
        parts = text[len(prefix) :].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["max_nodes"] = int(parts[1])
            if len(parts) >= 3 and parts[2].isdigit():
                arguments["max_edges"] = int(parts[2])
            return CommandPlan(intent="evidence_graph", steps=[ToolCall(tool="forensic.evidence_graph", arguments=arguments)])
    if lower.startswith("graph neighbors "):
        parts = text[len("graph neighbors ") :].strip().split(maxsplit=3)
        if len(parts) >= 2:
            arguments: dict[str, object] = {"case_id": parts[0], "query": parts[1]}
            if len(parts) >= 3 and parts[2].isdigit():
                arguments["depth"] = int(parts[2])
            if len(parts) == 4 and parts[3].isdigit():
                arguments["max_results"] = int(parts[3])
            return CommandPlan(intent="graph_neighbors", steps=[ToolCall(tool="forensic.graph_neighbors", arguments=arguments)])
    if lower.startswith("graph trace "):
        parts = text[len("graph trace ") :].strip().split()
        if len(parts) >= 3:
            arguments: dict[str, object] = {"case_id": parts[0], "source": parts[1], "target": parts[2]}
            if len(parts) >= 4 and parts[3].isdigit():
                arguments["max_hops"] = int(parts[3])
            return CommandPlan(intent="graph_trace", steps=[ToolCall(tool="forensic.graph_trace", arguments=arguments)])
    if lower.startswith("attack mapping ") or lower.startswith("mitre mapping "):
        prefix = "attack mapping " if lower.startswith("attack mapping ") else "mitre mapping "
        parts = text[len(prefix) :].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["max_candidates"] = int(parts[1])
            return CommandPlan(intent="attack_mapping", steps=[ToolCall(tool="forensic.attack_mapping", arguments=arguments)])
    if lower.startswith("attack chain "):
        parts = text[len("attack chain ") :].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["max_candidates"] = int(parts[1])
            return CommandPlan(intent="attack_chain", steps=[ToolCall(tool="forensic.attack_chain", arguments=arguments)])
    if lower in {"yara status", "check yara"}:
        return CommandPlan(intent="yara_status", steps=[ToolCall(tool="forensic.yara_status")])
    if lower.startswith("yara evidence "):
        parts = text[len("yara evidence ") :].strip().split(maxsplit=2)
        if len(parts) == 3:
            return CommandPlan(intent="yara_scan_evidence", steps=[ToolCall(tool="forensic.yara_scan_evidence", arguments={"case_id": parts[0], "evidence_id": parts[1], "rule_path": parts[2]})])
    if lower.startswith("correlate ") or lower.startswith("analyze case "):
        prefix = "correlate " if lower.startswith("correlate ") else "analyze case "
        parts = text[len(prefix) :].strip().split()
        if parts:
            arguments = {"case_id": parts[0]}
            if len(parts) >= 2 and parts[1].isdigit():
                arguments["window_seconds"] = int(parts[1])
            return CommandPlan(intent="correlate_forensic_case", steps=[ToolCall(tool="forensic.correlate_case", arguments=arguments)])
    if lower.startswith("collect macos logs "):
        parts = text[len("collect macos logs ") :].strip().split()
        if parts:
            arguments: dict[str, object] = {"case_id": parts[0]}
            if len(parts) >= 2:
                arguments["last"] = parts[1]
            return CommandPlan(intent="collect_macos_logs", steps=[ToolCall(tool="forensic.collect_macos_logs", arguments=arguments)])
    if lower in {"volatility status", "check volatility"}:
        return CommandPlan(intent="volatility_status", steps=[ToolCall(tool="forensic.volatility_status")])
    if lower.startswith("volatility evidence "):
        parts = text[len("volatility evidence ") :].strip().split()
        if len(parts) == 3:
            return CommandPlan(intent="run_volatility_evidence", steps=[ToolCall(tool="forensic.run_volatility_evidence", arguments={"case_id": parts[0], "evidence_id": parts[1], "plugin": parts[2]})])
    if lower.startswith("volatility run "):
        parts = text[len("volatility run ") :].strip().split(maxsplit=3)
        if len(parts) >= 3:
            arguments: dict[str, object] = {"case_id": parts[0], "plugin": parts[1], "image_path": parts[2]}
            if len(parts) == 4:
                arguments["evidence_id"] = parts[3]
            return CommandPlan(intent="run_volatility", steps=[ToolCall(tool="forensic.run_volatility", arguments=arguments)])
    if lower in {"tshark status", "check tshark"}:
        return CommandPlan(intent="tshark_status", steps=[ToolCall(tool="forensic.tshark_status")])
    if lower.startswith("create sample pcap"):
        path = text[len("create sample pcap") :].strip() or "workspace/sample.pcap"
        return CommandPlan(intent="create_sample_pcap", steps=[ToolCall(tool="forensic.create_sample_pcap", arguments={"path": path})])
    if lower.startswith("pcap evidence "):
        parts = text[len("pcap evidence ") :].strip().split()
        if len(parts) >= 2:
            arguments: dict[str, object] = {"case_id": parts[0], "evidence_id": parts[1]}
            if len(parts) >= 3 and parts[2].isdigit():
                arguments["max_packets"] = int(parts[2])
            return CommandPlan(intent="analyze_pcap_evidence", steps=[ToolCall(tool="forensic.analyze_pcap_evidence", arguments=arguments)])

    return CommandPlan(intent="unknown", requires_action=False, steps=[])
