from __future__ import annotations

import argparse
import json
import subprocess
import sys


def run(command: list[str]) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel AI release validation gate")
    parser.add_argument("--benchmark-events", type=int, default=10000)
    parser.add_argument("--skip-benchmark", action="store_true")
    args = parser.parse_args()

    run([sys.executable, "-m", "compileall", "-q", "app"])
    run([sys.executable, "-m", "pytest", "-q", "--tb=short"])
    if not args.skip_benchmark:
        run([sys.executable, "scripts/benchmark_scale.py", "--events", str(args.benchmark_events)])
    print(json.dumps({"status": "release-check-passed", "benchmark_events": 0 if args.skip_benchmark else args.benchmark_events}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
