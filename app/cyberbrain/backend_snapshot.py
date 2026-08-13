from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.cyberbrain.platform_status import sentinel_x_status


class BackendSnapshotService:
    VERSION = "backend-snapshot-v1"

    def __init__(self, data_root: str | Path = "data") -> None:
        self.root = Path(data_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def manifest(self) -> dict[str, Any]:
        return {
            "version": self.VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "platform": sentinel_x_status(self.root),
            "stores": {
                "evaluation_lab": str(self.root / "evaluation_lab.db"),
                "shared_insights": str(self.root / "shared_insights.json"),
                "knowledge": str(self.root / "cyber_knowledge.db"),
                "engagements": str(self.root / "engagements.db"),
                "privilege_graph": str(self.root / "privilege_graph.db"),
                "digital_twin": str(self.root / "digital_twin.db"),
                "control_plane": str(self.root / "control_plane.db"),
            },
        }

    def write_manifest(self, output: str | Path | None = None) -> Path:
        target = Path(output) if output else self.root / "backend_manifest.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.manifest(), indent=2, sort_keys=True), encoding="utf-8")
        return target
