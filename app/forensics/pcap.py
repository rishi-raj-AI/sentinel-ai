from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineEvent, TimelineStore


class TsharkAdapter:
    """Controlled tshark adapter for registered/authorized PCAP analysis."""

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.store = TimelineStore(case_dir)

    @staticmethod
    def executable() -> str | None:
        return shutil.which("tshark")

    @classmethod
    def status(cls) -> dict[str, Any]:
        executable = cls.executable()
        if not executable:
            return {"available": False, "executable": None, "message": "tshark not found on PATH"}
        completed = subprocess.run([executable, "-v"], capture_output=True, text=True, timeout=20, check=False)
        return {
            "available": completed.returncode == 0,
            "executable": executable,
            "return_code": completed.returncode,
            "version": (completed.stdout or completed.stderr).splitlines()[0] if (completed.stdout or completed.stderr) else None,
        }

    def analyze(self, pcap_path: str, *, evidence_id: str | None = None, max_packets: int = 5000) -> dict[str, Any]:
        executable = self.executable()
        if not executable:
            raise RuntimeError("tshark is not installed or not on PATH")

        pcap = Path(pcap_path).expanduser().resolve()
        if not pcap.is_file():
            raise FileNotFoundError(f"PCAP not found: {pcap}")

        fields = [
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "dns.qry.name",
            "http.host",
            "tls.handshake.extensions_server_name",
            "_ws.col.Protocol",
        ]

        command = [
            executable,
            "-r",
            str(pcap),
            "-T",
            "json",
            "-c",
            str(max_packets),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"tshark exited {completed.returncode}")

        try:
            packets = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("tshark did not return valid JSON") from exc

        events: list[TimelineEvent] = []
        for packet in packets:
            source = packet.get("_source", {}).get("layers", {}) if isinstance(packet, dict) else {}
            frame = source.get("frame", {}) if isinstance(source, dict) else {}
            ip = source.get("ip", {}) if isinstance(source, dict) else {}
            tcp = source.get("tcp", {}) if isinstance(source, dict) else {}
            udp = source.get("udp", {}) if isinstance(source, dict) else {}
            dns = source.get("dns", {}) if isinstance(source, dict) else {}
            http = source.get("http", {}) if isinstance(source, dict) else {}
            tls = source.get("tls", {}) if isinstance(source, dict) else {}

            epoch = frame.get("frame.time_epoch")
            timestamp = None
            if epoch:
                from datetime import datetime, timezone

                try:
                    timestamp = datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()
                except Exception:
                    timestamp = None

            src = ip.get("ip.src")
            dst = ip.get("ip.dst")
            proto = frame.get("frame.protocols") or "network"
            details = {
                "src": src,
                "dst": dst,
                "tcp_srcport": tcp.get("tcp.srcport"),
                "tcp_dstport": tcp.get("tcp.dstport"),
                "udp_srcport": udp.get("udp.srcport"),
                "udp_dstport": udp.get("udp.dstport"),
                "dns_query": dns.get("dns.qry.name"),
                "http_host": http.get("http.host"),
                "tls_sni": tls.get("tls.handshake.extensions_server_name"),
                "protocols": proto,
            }
            summary_parts = [str(x) for x in (src, "→" if src or dst else None, dst) if x]
            if details["dns_query"]:
                summary_parts.append(f"DNS={details['dns_query']}")
            if details["http_host"]:
                summary_parts.append(f"HTTP={details['http_host']}")
            if details["tls_sni"]:
                summary_parts.append(f"TLS={details['tls_sni']}")

            events.append(
                TimelineEvent(
                    timestamp=TimelineStore.normalize_timestamp(timestamp),
                    source="tshark",
                    event_type="network",
                    summary=" ".join(summary_parts) if summary_parts else "Network packet",
                    details=details,
                    evidence_id=evidence_id,
                )
            )

        ingested = self.store.extend(events)
        return {
            "pcap_path": str(pcap),
            "packets_parsed": len(packets),
            "events_ingested": ingested,
            "max_packets": max_packets,
        }
