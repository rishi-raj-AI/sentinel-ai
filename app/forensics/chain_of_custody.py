from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ChainOfCustody:
    def __init__(self, case_dir: Path) -> None:
        self.path = case_dir / "logs" / "chain_of_custody.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _previous_hash(self) -> str:
        if not self.path.exists():
            return "GENESIS"
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return "GENESIS"
        return json.loads(lines[-1])["record_hash"]

    def append(self, event: str, details: dict[str, Any]) -> dict[str, Any]:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
            "previous_hash": self._previous_hash(),
        }
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record["record_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        return record

    def verify(self) -> bool:
        if not self.path.exists():
            return True
        previous = "GENESIS"
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            stored_hash = record.pop("record_hash")
            if record.get("previous_hash") != previous:
                return False
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
            computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if computed != stored_hash:
                return False
            previous = stored_hash
        return True
