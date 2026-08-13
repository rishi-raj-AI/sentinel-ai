from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.autonomy.phase6 import Phase6Autonomy


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="sentinel-phase7-live-") as tmp:
        os.environ["SENTINEL_DATA_ROOT"] = tmp
        phase6 = Phase6Autonomy(tmp)
        mission = phase6.create_mission("Review source code and repository security", case_id="SELFTEST-LIVE")
        mission_id = mission["mission_id"]

        from scripts.phase7_stream_server import create_app

        client = TestClient(create_app())
        health = client.get("/healthz")
        snapshot = client.get(f"/api/x/operations/missions/{mission_id}")

        assert health.status_code == 200
        assert health.json()["read_only"] is True
        assert snapshot.status_code == 200
        payload = snapshot.json()
        assert payload["mission"]["mission_id"] == mission_id
        assert "events" in payload
        assert "evidence" in payload
        assert "supervisor" in payload
        assert "capability_plan" in payload

        print({
            "status": "phase7-live-selfcheck-passed",
            "mission_id": mission_id,
            "telemetry_read_only": True,
            "snapshot_fields": sorted(payload.keys()),
        })


if __name__ == "__main__":
    main()
