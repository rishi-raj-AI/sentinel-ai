from app.brain.planner import plan_command
from app.forensics.evtx_adapter import EvtxAdapter


PROCESS_XML = '''
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID>
    <Level>4</Level>
    <TimeCreated SystemTime="2026-08-12T20:00:00.000000Z"/>
    <EventRecordID>42</EventRecordID>
    <Execution ProcessID="100" ThreadID="200"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>LAB-PC</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="ProcessId">4321</Data>
    <Data Name="ParentProcessId">1234</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile</Data>
  </EventData>
</Event>
'''

AUTH_XML = '''
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-12T20:01:00Z"/>
    <Channel>Security</Channel>
    <Computer>LAB-PC</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
  </EventData>
</Event>
'''


def test_evtx_process_normalization():
    event = EvtxAdapter._normalize_xml(PROCESS_XML, "E0005")
    assert event is not None
    assert event.source == "evtx"
    assert event.event_type == "process"
    assert event.evidence_id == "E0005"
    assert event.details["event_id"] == "1"
    assert event.details["provider"] == "Microsoft-Windows-Sysmon"
    assert event.details["PID"] == "4321"
    assert event.details["PPID"] == "1234"
    assert "powershell.exe" in event.details["process"].lower()
    assert event.details["CommandLine"] == "powershell.exe -NoProfile"


def test_evtx_authentication_normalization():
    event = EvtxAdapter._normalize_xml(AUTH_XML, "E0006")
    assert event is not None
    assert event.event_type == "authentication"
    assert event.details["event_id"] == "4625"
    assert event.details["TargetUserName"] == "alice"


def test_evtx_status_shape():
    status = EvtxAdapter.status()
    assert "available" in status
    assert status["package"] == "python-evtx"


def test_evtx_planner_commands():
    status_plan = plan_command("evtx status")
    assert status_plan.steps[0].tool == "forensic.evtx_status"

    plan = plan_command("evtx evidence DFIR-2026-0001 E0005 2500")
    assert plan.steps[0].tool == "forensic.evtx_analyze_evidence"
    assert plan.steps[0].arguments == {
        "case_id": "DFIR-2026-0001",
        "evidence_id": "E0005",
        "max_events": 2500,
    }
