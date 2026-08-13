# Sentinel X Backend

Sentinel X exposes the backend generation X1-X12 under `/api/x` in addition to the existing case, enterprise, SOC, autonomous-investigation, health, readiness and metrics APIs.

## Core API families

- `/api/x/skills`, `/api/x/plan` — capability discovery and decision planning.
- `/api/x/knowledge/*` — normalized knowledge ingestion, search, statistics and graph neighbors.
- `/api/x/engagements/*` — scoped engagement, asset, finding and review-plan workflows.
- `/api/x/artifacts/analyze` — local static artifact analysis restricted to the configured artifact root.
- `/api/x/privileges/*` — cloud/identity privilege graph ingestion, risk and path queries.
- `/api/x/appsec/analyze` — static project and software-supply-chain analysis restricted to the configured projects root.
- `/api/x/twin/*` — digital-twin ingestion, coverage and simulation.
- `/api/x/fusion/evaluate` — cross-domain decision-support fusion.
- `/api/x/control/*` — tenant policy, authorization and audit decisions.
- `/api/x/evaluation/*` — evaluation scenarios, results and leaderboard.
- `/api/x/insights/*` — de-identified shared-insight storage and retrieval.
- `/api/x/status` — unified X1-X12 platform status.

## Data contract

The backend uses `SENTINEL_DATA_ROOT` (default `data`) for X-generation stores. The primary persistent stores are:

- `cyber_knowledge.db`
- `engagements.db`
- `privilege_graph.db`
- `digital_twin.db`
- `control_plane.db`
- `evaluation_lab.db`
- `shared_insights.json`

`BackendSnapshotService` writes `backend_manifest.json` with the current X-generation status and store paths. The release gate creates this manifest automatically.

## External data integrations

External sources should normalize records before posting to `/api/x/knowledge/ingest`. This keeps provider-specific credentials and schemas outside the core data model. Source adapters may target public vulnerability/advisory catalogs, ATT&CK-style behavioral knowledge, vendor advisories or private organizational feeds without changing Sentinel's entity/relation contract.

Credentials and endpoints must be supplied by deployment configuration/environment variables and should never be embedded in frontend code.

## Authorization

Existing Sentinel RBAC applies to the X APIs. Read operations generally require `case.read`; backend mutations require `workspace.write` or `review.write` depending on impact. Tenant authorization decisions are recorded in the X10 audit store.

## Safety and data boundaries

- Artifact/project analyzers are confined to configured backend directories.
- Digital-twin path analysis is simulation-only.
- Fusion is decision support and does not perform automatic remediation.
- Shared insights reject direct identifiers/raw customer material and enforce a minimum source threshold.
- Higher-autonomy X10 decisions can require human approval.

## Backend release gate

Run:

```bash
python scripts/release_check.py --benchmark-events 10000
```

The gate compiles application modules, runs pytest, runs the scale benchmark unless disabled, and writes `data/backend_manifest.json`.

Before frontend work, also verify:

```bash
curl -s http://127.0.0.1:8765/api/x/status | python -m json.tool
curl -s http://127.0.0.1:8765/api/x/evaluation/summary | python -m json.tool
curl -s http://127.0.0.1:8765/api/x/insights/stats | python -m json.tool
```
