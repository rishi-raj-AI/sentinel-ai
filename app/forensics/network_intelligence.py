from __future__ import annotations

import ipaddress
from collections import Counter
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineStore


class NetworkIntelligenceEngine:
    """Aggregate normalized network events into investigator-friendly flows."""

    DOCUMENTATION_NETWORKS = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )

    def __init__(self, case_dir: str | Path) -> None:
        self.store = TimelineStore(case_dir)

    @classmethod
    def _ip_scope(cls, value: str | None) -> str:
        if not value:
            return "unknown"
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return "invalid"
        if any(ip in network for network in cls.DOCUMENTATION_NETWORKS):
            return "documentation"
        if ip.is_loopback:
            return "loopback"
        if ip.is_multicast:
            return "multicast"
        if ip.is_link_local:
            return "link_local"
        if ip.is_private:
            return "private"
        if ip.is_reserved:
            return "reserved"
        return "public"

    @staticmethod
    def _port(details: dict[str, Any], side: str) -> str | None:
        return details.get(f"tcp_{side}port") or details.get(f"udp_{side}port")

    @staticmethod
    def _primary_protocol(protocols: list[str] | set[str]) -> str | None:
        tokens: list[str] = []
        for value in protocols:
            tokens.extend(part.strip().lower() for part in str(value).split(":") if part.strip())
        for candidate in ("tcp", "udp", "icmp", "icmpv6"):
            if candidate in tokens:
                return candidate.upper()
        return tokens[-1].upper() if tokens else None

    def analyze(self, *, max_flows: int = 100) -> dict[str, Any]:
        events = [event for event in self.store.read() if event.get("event_type") == "network"]
        flows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        dns_queries: Counter[str] = Counter()
        http_hosts: Counter[str] = Counter()
        tls_hosts: Counter[str] = Counter()
        destination_scopes: Counter[str] = Counter()
        source_scopes: Counter[str] = Counter()
        ignored_events = 0

        for event in events:
            details = event.get("details") or {}
            src = str(details.get("src") or "")
            dst = str(details.get("dst") or "")
            if not src and not dst:
                ignored_events += 1
                continue

            src_port = str(self._port(details, "src") or "")
            dst_port = str(self._port(details, "dst") or "")
            key = (src, src_port, dst, dst_port)
            flow = flows.setdefault(
                key,
                {
                    "src": src or None,
                    "src_port": src_port or None,
                    "dst": dst or None,
                    "dst_port": dst_port or None,
                    "packet_count": 0,
                    "first_seen": event.get("timestamp"),
                    "last_seen": event.get("timestamp"),
                    "evidence_ids": set(),
                    "protocols": set(),
                },
            )
            flow["packet_count"] += 1
            flow["last_seen"] = event.get("timestamp")
            if event.get("evidence_id"):
                flow["evidence_ids"].add(event["evidence_id"])
            if details.get("protocols"):
                flow["protocols"].add(str(details["protocols"]))

            source_scopes[self._ip_scope(src)] += 1
            destination_scopes[self._ip_scope(dst)] += 1

            if details.get("dns_query"):
                dns_queries[str(details["dns_query"])] += 1
            if details.get("http_host"):
                http_hosts[str(details["http_host"])] += 1
            if details.get("tls_sni"):
                tls_hosts[str(details["tls_sni"])] += 1

        rendered_flows = []
        for flow in sorted(flows.values(), key=lambda item: item["packet_count"], reverse=True)[:max_flows]:
            rendered = dict(flow)
            rendered["evidence_ids"] = sorted(flow["evidence_ids"])
            rendered["protocols"] = sorted(flow["protocols"])
            rendered["protocol"] = self._primary_protocol(flow["protocols"])
            rendered["src_scope"] = self._ip_scope(flow["src"])
            rendered["dst_scope"] = self._ip_scope(flow["dst"])
            rendered_flows.append(rendered)

        public_destinations = [flow for flow in rendered_flows if flow.get("dst_scope") == "public"]
        unusual_ports = [
            flow
            for flow in rendered_flows
            if flow.get("dst_port") and str(flow["dst_port"]) not in {"53", "80", "123", "443"}
        ]

        return {
            "network_event_count": len(events),
            "network_events_ignored": ignored_events,
            "flow_count": len(flows),
            "flows": rendered_flows,
            "dns_queries": dict(dns_queries.most_common(50)),
            "http_hosts": dict(http_hosts.most_common(50)),
            "tls_sni": dict(tls_hosts.most_common(50)),
            "source_scopes": dict(source_scopes),
            "destination_scopes": dict(destination_scopes),
            "findings": {
                "public_destination_flows": public_destinations,
                "unusual_destination_ports": unusual_ports,
            },
        }
