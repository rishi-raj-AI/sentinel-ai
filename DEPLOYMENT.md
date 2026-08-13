# Sentinel AI deployment and production-hardening guide

## Local production-style run

Use the existing virtual environment and start without auto-reload:

```bash
python -m app.web --host 127.0.0.1 --port 8765
```

Operational endpoints:

- `/healthz` — liveness
- `/readyz` — readiness
- `/metrics` — Prometheus text metrics

Set `SENTINEL_MAX_REQUEST_BYTES` to cap accepted HTTP request bodies. The default is 2 MiB.

## Container deployment

```bash
docker compose build
docker compose up -d
curl http://127.0.0.1:8765/healthz
```

The supplied container runs as a non-root user, drops Linux capabilities, sets `no-new-privileges`, uses a read-only root filesystem, and mounts only `cases`, `logs`, and `config` as persistent data paths.

## Scale validation

Run the deterministic benchmark harness before release:

```bash
python scripts/benchmark_scale.py --events 10000
python scripts/benchmark_scale.py --events 100000
```

Record ingest, network-analysis, and graph-build times on the target hardware. These are benchmarks rather than fixed performance promises; release thresholds should be defined from measured production hardware and representative case data.

## Release validation

```bash
python -m pytest -q --tb=short
python -m compileall -q app
python scripts/benchmark_scale.py --events 10000
docker compose config
```

Then validate `/healthz`, `/readyz`, `/metrics`, the enterprise APIs, and a read-only SOC run.

## Production boundaries

The current platform provides local RBAC enforcement and durable local state, but header-based roles are not enterprise identity. Deploy behind an authenticated reverse proxy or identity-aware gateway until native SSO/OIDC is implemented. The SQLite job/workspace stores are appropriate for a single-node deployment; distributed workers and multi-node transactional storage require a later infrastructure migration.
