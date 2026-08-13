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
    rows = registry.health()
    payload = {
        "version": registry.VERSION,
        "installed_count": sum(1 for row in rows if row["installed"]),
        "total_count": len(rows),
        "tools": rows,
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
