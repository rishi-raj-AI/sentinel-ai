from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.integration import ToolRegistry


def main() -> int:
    registry = ToolRegistry()
    summary = registry.summary()
    packs: dict[str, dict[str, object]] = {}
    for pack, ids in summary["packs"].items():
        rows = [row for row in summary["tools"] if row["tool_id"] in ids]
        packs[pack] = {
            "ready": sum(1 for row in rows if row["ready"]),
            "total": len(rows),
            "tools": [
                {
                    "tool_id": row["tool_id"],
                    "ready": row["ready"],
                    "installed": row["installed"],
                    "compatible": row["compatible"],
                    "version": row["version"],
                    "profiles": row["profiles"],
                    "error": row["error"],
                }
                for row in rows
            ],
        }
    print(json.dumps({
        "version": summary["version"],
        "ready_count": summary["ready_count"],
        "total_count": summary["total_count"],
        "required_ready": summary["required_ready"],
        "required_total": summary["required_total"],
        "packs": packs,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
