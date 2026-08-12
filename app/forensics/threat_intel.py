from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from app.forensics.timeline import TimelineStore


class ThreatIntelEngine:
    """Local IOC inventory and classification without external lookups.

    This deliberately avoids sending case artifacts to third-party services. It
    inventories observed IPs/domains and registered evidence hashes so an online
    enrichment provider can be added later with explicit configuration.
    """

    DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.timeline = TimelineStore(case_dir)

    @staticmethod
    def _ip_scope(value: str) -> str:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return "invalid"
        if ip.is_loopback:
            return "loopback"
        if ip.is_link_local:
            return "link_local"
        if ip.is_multicast:
            return "multicast"
        if ip.is_private:
            return "private"
        if value.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) or value.lower().startswith("2001:db8:"):
            return "documentation"
        return "public"

    def inventory(self, *, max_items: int = 200) -> dict[str, Any]:
        ips: dict[str, dict[str, Any]] = {}
        domains: dict[str, dict[str, Any]] = {}
        for event in self.timeline.read():
            details = event.get("details") or {}
            evidence_id = event.get("evidence_id")
            for key in ("src", "dst", "SourceIp", "DestinationIp", "LocalAddr", "ForeignAddr"):
                value = details.get(key)
                if not value:
                    continue
                text = str(value).strip()
                try:
                    ipaddress.ip_address(text)
                except ValueError:
                    continue
                item = ips.setdefault(text, {"indicator": text, "type": "ip", "scope": self._ip_scope(text), "evidence_ids": set(), "count": 0})
                item["count"] += 1
                if evidence_id:
                    item["evidence_ids"].add(str(evidence_id))
            for key in ("dns_query", "http_host", "tls_sni"):
                value = details.get(key)
                if not value:
                    continue
                text = str(value).strip().lower().rstrip(".")
                if not self.DOMAIN_RE.fullmatch(text):
                    continue
                item = domains.setdefault(text, {"indicator": text, "type": "domain", "evidence_ids": set(), "count": 0})
                item["count"] += 1
                if evidence_id:
                    item["evidence_ids"].add(str(evidence_id))

        hashes: list[dict[str, Any]] = []
        case_json = self.case_dir / "case.json"
        if case_json.is_file():
            try:
                record = json.loads(case_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                record = {}
            for evidence in record.get("evidence", []):
                sha256 = evidence.get("sha256")
                if sha256:
                    hashes.append({
                        "indicator": str(sha256),
                        "type": "sha256",
                        "evidence_id": evidence.get("evidence_id"),
                        "filename": evidence.get("filename"),
                    })

        def clean(item: dict[str, Any]) -> dict[str, Any]:
            out = dict(item)
            if isinstance(out.get("evidence_ids"), set):
                out["evidence_ids"] = sorted(out["evidence_ids"])
            return out

        ip_rows = [clean(v) for v in ips.values()][:max_items]
        domain_rows = [clean(v) for v in domains.values()][:max_items]
        return {
            "ips": ip_rows,
            "domains": domain_rows,
            "hashes": hashes[:max_items],
            "summary": {
                "ip_count": len(ips),
                "public_ip_count": sum(1 for row in ips.values() if row["scope"] == "public"),
                "domain_count": len(domains),
                "hash_count": len(hashes),
                "external_lookup_performed": False,
            },
            "note": "No case indicators were transmitted externally. Online enrichment can be added later with explicit provider configuration.",
        }
