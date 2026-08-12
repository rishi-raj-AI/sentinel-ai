from __future__ import annotations

import importlib.util
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineEvent, TimelineStore


class EvtxAdapter:
    """Parse Windows .evtx evidence into normalized Sentinel timeline events."""

    NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.timeline = TimelineStore(case_dir)

    @staticmethod
    def status() -> dict[str, Any]:
        available = importlib.util.find_spec("Evtx") is not None
        version = None
        if available:
            try:
                import importlib.metadata as metadata
                version = metadata.version("python-evtx")
            except Exception:
                version = None
        return {
            "available": available,
            "package": "python-evtx",
            "version": version,
            "message": "ready" if available else "python-evtx is not installed",
        }

    @staticmethod
    def _valid_magic(path: Path) -> bool:
        with path.open("rb") as handle:
            return handle.read(7) == b"ElfFile"

    @classmethod
    def _normalize_xml(cls, xml_text: str, evidence_id: str | None) -> TimelineEvent | None:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        system = root.find("e:System", cls.NS)
        if system is None:
            return None

        def text(path: str) -> str | None:
            node = system.find(path, cls.NS)
            return node.text.strip() if node is not None and node.text else None

        provider_node = system.find("e:Provider", cls.NS)
        time_node = system.find("e:TimeCreated", cls.NS)
        execution_node = system.find("e:Execution", cls.NS)
        security_node = system.find("e:Security", cls.NS)

        provider = provider_node.attrib.get("Name") if provider_node is not None else None
        timestamp = time_node.attrib.get("SystemTime") if time_node is not None else None
        event_id = text("e:EventID")
        channel = text("e:Channel")
        computer = text("e:Computer")
        level = text("e:Level")
        record_id = text("e:EventRecordID")

        event_data: dict[str, Any] = {}
        data_root = root.find("e:EventData", cls.NS)
        if data_root is not None:
            unnamed = 0
            for node in data_root.findall("e:Data", cls.NS):
                name = node.attrib.get("Name")
                if not name:
                    unnamed += 1
                    name = f"Data{unnamed}"
                value = node.text or ""
                if name in event_data:
                    current = event_data[name]
                    event_data[name] = current + [value] if isinstance(current, list) else [current, value]
                else:
                    event_data[name] = value

        user_data = root.find("e:UserData", cls.NS)
        if user_data is not None:
            event_data["UserDataXML"] = ET.tostring(user_data, encoding="unicode")[:4000]

        process_id = execution_node.attrib.get("ProcessID") if execution_node is not None else None
        thread_id = execution_node.attrib.get("ThreadID") if execution_node is not None else None
        user_id = security_node.attrib.get("UserID") if security_node is not None else None

        details = {
            "provider": provider,
            "event_id": event_id,
            "channel": channel,
            "computer": computer,
            "level": level,
            "record_id": record_id,
            "process_id": process_id,
            "thread_id": thread_id,
            "user_id": user_id,
            **event_data,
        }

        # Promote common fields to the names already understood by Sentinel's graph.
        for source_key, target_key in (
            ("Image", "process"),
            ("NewProcessName", "process"),
            ("ProcessName", "process"),
            ("ProcessId", "PID"),
            ("NewProcessId", "PID"),
            ("ParentProcessId", "PPID"),
            ("ParentProcessName", "ParentProcessName"),
            ("CommandLine", "CommandLine"),
            ("TargetFilename", "path"),
            ("ObjectName", "path"),
            ("DestinationIp", "dst"),
            ("SourceIp", "src"),
            ("DestinationPort", "tcp_dstport"),
            ("SourcePort", "tcp_srcport"),
        ):
            if source_key in event_data and event_data[source_key] not in (None, ""):
                details[target_key] = event_data[source_key]

        event_type = "windows_event"
        if event_id in {"1", "4688"}:
            event_type = "process"
        elif event_id in {"3", "5156"}:
            event_type = "network"
        elif event_id in {"11", "4663"}:
            event_type = "file"
        elif event_id in {"4624", "4625", "4648"}:
            event_type = "authentication"

        summary = f"{provider or 'Windows Event'} EventID={event_id or '?'}"
        if event_data.get("Image") or event_data.get("NewProcessName"):
            summary += f" process={event_data.get('Image') or event_data.get('NewProcessName')}"

        return TimelineEvent(
            timestamp=TimelineStore.normalize_timestamp(timestamp),
            source="evtx",
            event_type=event_type,
            summary=summary[:1000],
            details=details,
            evidence_id=evidence_id,
        )

    def analyze(self, evtx_path: str, *, evidence_id: str | None = None, max_events: int = 5000) -> dict[str, Any]:
        status = self.status()
        if not status["available"]:
            raise RuntimeError("python-evtx is not installed")
        if max_events < 1 or max_events > 100000:
            raise ValueError("max_events must be between 1 and 100000")

        path = Path(evtx_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"EVTX file not found: {path}")
        if not self._valid_magic(path):
            raise ValueError(f"File is not a valid EVTX container: {path}")

        from Evtx.Evtx import Evtx

        events: list[TimelineEvent] = []
        skipped = 0
        with Evtx(str(path)) as log:
            for record in log.records():
                event = self._normalize_xml(record.xml(), evidence_id)
                if event is None:
                    skipped += 1
                    continue
                events.append(event)
                if len(events) >= max_events:
                    break

        ingested = self.timeline.extend(events)
        by_type: dict[str, int] = {}
        by_provider: dict[str, int] = {}
        for event in events:
            by_type[event.event_type] = by_type.get(event.event_type, 0) + 1
            provider = str(event.details.get("provider") or "unknown")
            by_provider[provider] = by_provider.get(provider, 0) + 1

        return {
            "evtx_path": str(path),
            "events_ingested": ingested,
            "skipped": skipped,
            "max_events": max_events,
            "by_type": by_type,
            "by_provider": by_provider,
        }
