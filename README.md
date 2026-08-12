# Sentinel AI

Sentinel AI is a local-first personal AI assistant and digital-forensics automation project.

## Phase 1 status

The current foundation implements a controlled execution pipeline:

`command -> structured plan -> registered tool -> risk classification -> execution -> audit`

Only a small read-only tool set is enabled in this phase. There is no unrestricted shell execution.

## Requirements

- Python 3.12+
- Git

## Setup

```bash
git checkout phase1-foundation
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run tests

```bash
pytest -q
```

## Try the CLI

```bash
python main.py run "system info"
python main.py run "disk usage /"
python main.py run "list ."
python main.py run "read README.md"
python main.py run "sha256 README.md"
```

Local actions are written to `logs/audit.db`; the database is intentionally ignored by Git.

## Next milestone

- model-backed planner using the same validated `CommandPlan` schema
- modification tools with explicit confirmation
- persistent assistant memory
- forensic case/evidence manager
