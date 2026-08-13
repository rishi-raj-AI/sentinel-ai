from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SharedInsight:
    category: str
    summary: str
    confidence: float
    frequency: int
    source_count: int
    attributes: dict[str, Any] | None = None


class SharedInsightStore:
    """Local store for de-identified, generalized insight bundles."""

    VERSION = "X12.0"

    def __init__(self, path: str | Path, *, minimum_sources: int = 2) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.minimum_sources = max(2, int(minimum_sources))
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def _load(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = []
        return data if isinstance(data, list) else []

    def add(self, insight: SharedInsight) -> dict[str, Any]:
        if not 0 <= float(insight.confidence) <= 1:
            raise ValueError("confidence must be between 0 and 1")
        if int(insight.source_count) < self.minimum_sources:
            raise ValueError("insight does not meet the minimum source threshold")
        attrs = dict(insight.attributes or {})
        forbidden = {"tenant_id", "case_id", "raw", "content", "artifact_path", "username", "email", "address"}
        if forbidden.intersection({str(k).casefold() for k in attrs}):
            raise ValueError("direct identifiers or raw source material are not accepted")
        payload = asdict(insight)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        payload["insight_id"] = hashlib.sha256(canonical.encode()).hexdigest()[:20]
        payload["created_at"] = datetime.now(timezone.utc).isoformat()
        rows = self._load()
        if not any(row.get("insight_id") == payload["insight_id"] for row in rows):
            rows.append(payload)
            self.path.write_text(json.dumps(rows, indent=2, sort_keys=True), encoding="utf-8")
        return payload

    def list(self, *, category: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._load()
        if category:
            rows = [row for row in rows if row.get("category") == category]
        rows.sort(key=lambda row: (int(row.get("frequency") or 0), float(row.get("confidence") or 0)), reverse=True)
        return rows[: max(1, min(int(limit), 500))]

    def stats(self) -> dict[str, Any]:
        rows = self._load()
        return {"version": self.VERSION, "insight_count": len(rows), "minimum_sources": self.minimum_sources, "policy": {"deidentified_only": True, "raw_source_material_stored": False, "minimum_source_threshold": True}}
