from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.autonomy.phase7 import MissionOperations


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sentinel-phase7-") as tmp:
        ops = MissionOperations(tmp)
        mission = ops.phase6.create_mission("Review source code and repository security", case_id="SELFTEST-P7")
        mid = mission["mission_id"]
        cap = ops.capabilities.plan(mission["objective"])
        if not cap["capabilities"]:
            raise RuntimeError("capability planner returned no capabilities")
        ops.emit(mid, "mission.selfcheck", actor="phase7-selfcheck", payload={"case_id": "SELFTEST-P7"})
        ops.index_evidence(mid, evidence_type="context", label="Self-check context", source="selfcheck", stage_id="S1", confidence=1.0, case_id="SELFTEST-P7")
        supervisor = ops.refresh_supervisor(mid)
        snapshot = ops.snapshot(mid)
        checks = {
            "mission_created": snapshot["mission"]["mission_id"] == mid,
            "capabilities_present": len(snapshot["capability_plan"]["capabilities"]) >= 1,
            "events_persisted": len(snapshot["events"]) >= 2,
            "evidence_indexed": len(snapshot["evidence"]) == 1,
            "supervisor_scored": 0.0 <= supervisor["confidence"] <= 1.0,
            "snapshot_version": snapshot["version"] == "phase7-v1",
        }
        status = "phase7-selfcheck-passed" if all(checks.values()) else "phase7-selfcheck-failed"
        print(json.dumps({"status": status, "checks": checks, "mission_id": mid, "supervisor": supervisor}, indent=2))
        return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
