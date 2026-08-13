from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.autonomy.phase7 import MissionOperations


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel Phase 7 mission operations report")
    parser.add_argument("--data-root", default="data")
    parser.add_argument("--mission")
    parser.add_argument("--capabilities")
    parser.add_argument("--events", action="store_true")
    parser.add_argument("--evidence", action="store_true")
    parser.add_argument("--supervisor", action="store_true")
    args = parser.parse_args()

    ops = MissionOperations(args.data_root)
    if args.capabilities:
        payload = ops.capabilities.plan(args.capabilities)
    elif args.mission and args.events:
        payload = {"mission_id": args.mission, "events": ops.events(args.mission)}
    elif args.mission and args.evidence:
        payload = {"mission_id": args.mission, "evidence": ops.evidence(args.mission)}
    elif args.mission and args.supervisor:
        payload = ops.refresh_supervisor(args.mission)
    elif args.mission:
        payload = ops.snapshot(args.mission)
    else:
        parser.error("provide --mission or --capabilities")
        return 2

    print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
