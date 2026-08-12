from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.timeline import TimelineEvent, TimelineStore


def test_graph_extracts_macos_process_interface_and_ports(tmp_path):
    case_dir = tmp_path / "DFIR-GRAPH-MAC"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:42:33.824286+00:00",
        source="macos_unified_log",
        event_type="default",
        summary="kernel: udp_connection_summary",
        details={
            "process": "kernel",
            "process_id": 0,
            "message": "udp_connection_summary [192.0.2.10:50723<->198.51.100.20:443] interface: en0 process: Google Chrome Helper Duration: 29.731 sec",
        },
    ))

    result = EvidenceGraphEngine(case_dir).build()
    node_types = result["summary"]["nodes_by_type"]
    edge_types = result["summary"]["edges_by_relation"]

    assert node_types["process"] >= 2
    assert node_types["interface"] == 1
    assert node_types["port"] == 2
    assert node_types["ip"] == 2
    assert edge_types["used_interface"] >= 1
    assert edge_types["connected_via_port"] >= 1


def test_graph_extracts_volatility_process_parent_and_module(tmp_path):
    case_dir = tmp_path / "DFIR-GRAPH-VOL"
    store = TimelineStore(case_dir)
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:00:00+00:00",
        source="volatility:windows.pslist",
        event_type="process",
        summary="System",
        details={"ImageFileName": "System", "PID": 4, "PPID": 0},
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:00:01+00:00",
        source="volatility:windows.pslist",
        event_type="process",
        summary="cmd.exe",
        details={"ImageFileName": "cmd.exe", "PID": 100, "PPID": 4},
    ))
    store.append(TimelineEvent(
        timestamp="2026-08-12T18:00:02+00:00",
        source="volatility:windows.dlllist",
        event_type="module",
        summary="kernel32.dll",
        details={"ImageFileName": "cmd.exe", "PID": 100, "Path": "C:/Windows/System32/kernel32.dll"},
    ))

    result = EvidenceGraphEngine(case_dir).build()
    assert result["summary"]["nodes_by_type"]["process"] >= 2
    assert result["summary"]["nodes_by_type"]["module"] == 1
    assert result["summary"]["edges_by_relation"]["spawned"] == 1
    assert result["summary"]["edges_by_relation"]["loaded"] == 1
