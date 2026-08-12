from app.forensics.case_manager import CaseManager
from app.forensics.timeline import TimelineEvent, TimelineStore
from app.tools.forensics import investigate_case


def test_integrated_investigation_uses_flow_level_network_findings(tmp_path, monkeypatch):
    cases_root = tmp_path / "cases"
    case_manager = CaseManager(str(cases_root))
    case = case_manager.create_case("Integrated network test")
    case_dir = cases_root / case["case_id"]
    store = TimelineStore(case_dir)

    store.append(TimelineEvent(
        timestamp="2026-08-12T19:30:00+00:00",
        source="tshark",
        event_type="network",
        summary="192.0.2.10 → 198.51.100.20",
        details={
            "src": "192.0.2.10",
            "dst": "198.51.100.20",
            "udp_srcport": "54000",
            "udp_dstport": "4444",
            "protocols": "eth:ip:udp:data",
        },
        evidence_id="E0003",
    ))

    import app.tools.forensics as tools
    monkeypatch.setattr(tools.CaseManager, "root", cases_root)

    result = investigate_case(case["case_id"], window_seconds=120, max_findings=20)

    assert not any(
        finding.get("title") == "Priority network event"
        and (finding.get("events") or [{}])[0].get("source") == "tshark"
        for finding in result["findings"]
    )
    assert any(
        finding.get("title") == "Unusual destination port"
        for finding in result["network_findings"]
    )
    assert result["summary"]["network_finding_count"] == 1
