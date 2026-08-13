from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.autonomy.phase6 import Phase6Autonomy


def main() -> int:
    p = argparse.ArgumentParser(description="Sentinel Phase 6 trusted local mission worker")
    p.add_argument("--data-root", default="data")
    p.add_argument("--create", help="Create a mission from an objective")
    p.add_argument("--case-id")
    p.add_argument("--engagement-id")
    p.add_argument("--target")
    p.add_argument("--mission")
    p.add_argument("--prepare", action="store_true")
    p.add_argument("--approve", action="store_true")
    p.add_argument("--execute", action="store_true")
    p.add_argument("--actor", default="operator")
    p.add_argument("--path", help="Relative project/artifact path for confined local-analysis stages")
    p.add_argument("--list", action="store_true")
    p.add_argument("--memory", action="store_true")
    args = p.parse_args()

    svc = Phase6Autonomy(args.data_root)
    if args.create:
        out = svc.create_mission(args.create, case_id=args.case_id, engagement_id=args.engagement_id, target=args.target)
    elif args.list:
        out = {"version": svc.VERSION, "missions": svc.list_missions()}
    elif args.memory:
        out = {"version": svc.VERSION, "memory": svc.memory(case_id=args.case_id)}
    elif args.mission and args.prepare:
        out = svc.prepare(args.mission)
    elif args.mission and args.approve:
        out = svc.approve(args.mission, actor=args.actor)
    elif args.mission and args.execute:
        out = svc.execute(args.mission, actor=args.actor, path=args.path)
    elif args.mission:
        out = svc.get_mission(args.mission)
    else:
        p.error("choose --create, --list, --memory, or provide --mission with an action")
        return 2
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
