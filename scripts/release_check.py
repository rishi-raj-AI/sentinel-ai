from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.cyberbrain.backend_snapshot import BackendSnapshotService


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True, cwd=REPO_ROOT)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel AI release validation gate")
    parser.add_argument("--benchmark-events", type=int, default=10000)
    parser.add_argument("--skip-benchmark", action="store_true")
    args = parser.parse_args()

    run([sys.executable, "-m", "compileall", "-q", "app"])
    run([sys.executable, "-m", "pytest", "-q", "--tb=short"])
    if not args.skip_benchmark:
        run([sys.executable, "scripts/benchmark_scale.py", "--events", str(args.benchmark_events)])
    manifest = BackendSnapshotService(REPO_ROOT / "data").write_manifest()
    print(json.dumps({"status": "release-check-passed", "benchmark_events": 0 if args.skip_benchmark else args.benchmark_events, "backend_manifest": str(manifest)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
