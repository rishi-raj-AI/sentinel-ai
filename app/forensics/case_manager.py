from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CaseManager:
    def __init__(self, root: str = "cases") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _next_case_id(self) -> str:
        year = datetime.now(timezone.utc).year
        prefix = f"DFIR-{year}-"
        numbers: list[int] = []
        for item in self.root.iterdir():
            if item.is_dir() and item.name.startswith(prefix):
                try:
                    numbers.append(int(item.name.split("-")[-1]))
                except ValueError:
                    continue
        return f"{prefix}{(max(numbers, default=0) + 1):04d}"

    def create_case(self, title: str, description: str = "") -> dict[str, Any]:
        case_id = self._next_case_id()
        case_dir = self.root / case_id
        for name in ("evidence", "working", "exports", "reports", "logs"):
            (case_dir / name).mkdir(parents=True, exist_ok=True)

        record = {
            "case_id": case_id,
            "title": title,
            "description": description,
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "evidence": [],
        }
        (case_dir / "case.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    def load_case(self, case_id: str) -> dict[str, Any]:
        path = self.root / case_id / "case.json"
        if not path.exists():
            raise FileNotFoundError(f"Unknown forensic case: {case_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def save_case(self, record: dict[str, Any]) -> None:
        path = self.root / record["case_id"] / "case.json"
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
