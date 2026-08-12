# Sentinel AI

Sentinel AI is a local-first personal AI assistant and digital-forensics automation project.

## Current capabilities

Sentinel now includes a controlled execution pipeline, forensic case/evidence management, SHA-256 and chain-of-custody verification, timeline/correlation, macOS logs, Volatility, PCAP/TShark, YARA, EVTX, Sigma-style detection, an evidence graph, ATT&CK candidate mapping, case reasoning, IOC inventory, tamper-verifiable reports, a local investigation dashboard, and an evidence-grounded case copilot.

The execution model remains:

`command -> structured plan -> registered tool -> risk classification -> execution -> audit`

There is no unrestricted shell execution through the assistant tool registry.

## Requirements

- Python 3.12+
- Git

## Setup

```bash
git checkout phase1-foundation
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run tests

```bash
python -m pytest -q
```

## CLI examples

```bash
python main.py run "system info"
python main.py run "case brief DFIR-2026-0001 20"
python main.py run "sigma analyze DFIR-2026-0001 rules/sigma 25"
python main.py run "evidence graph DFIR-2026-0001 2500 5000"
python main.py run "export report DFIR-2026-0001 all 50 final-report"
python main.py run "verify report DFIR-2026-0001 final-report"
python main.py run "copilot status"
python main.py run "copilot ask DFIR-2026-0001 Why is UDP port 4444 worth reviewing?"
```

## Grounded case copilot

The copilot always performs case retrieval before answering. Retrieved sources use explicit IDs such as `EVIDENCE:E0003`, `SIGMA:<rule>`, `YARA:<evidence>:<rule>`, `FLOW:1`, `TIMELINE:42`, and `ATTACK:T1059.001:1`.

Without model configuration Sentinel stays fully usable and returns deterministic evidence-grounded answers. To enable model synthesis, configure an endpoint that accepts an OpenAI-compatible chat-completions request:

```bash
export SENTINEL_MODEL_ENDPOINT="http://127.0.0.1:YOUR_PORT/v1/chat/completions"
export SENTINEL_MODEL_NAME="YOUR_MODEL_NAME"
```

For endpoints requiring authentication:

```bash
export SENTINEL_MODEL_API_KEY="YOUR_API_KEY"
```

Optional request timeout:

```bash
export SENTINEL_MODEL_TIMEOUT="30"
```

Sentinel sends only the retrieved case context needed for the current question. Model answers must cite source IDs that were actually retrieved; answers with no valid Sentinel citations, unknown citations, provider errors, or timeouts are rejected and replaced with the deterministic grounded fallback.

Check the active mode with:

```bash
python main.py run "copilot status"
```

## Local investigation dashboard

Start the dashboard from the repository root:

```bash
python -m app.web
```

Then open:

```text
http://127.0.0.1:8765
```

The dashboard binds to loopback (`127.0.0.1`) by default. It provides case selection, assessment metrics, evidence inventory, timeline, Sigma/YARA detections, evidence-graph visualization, report access, and the grounded Investigator Copilot. Copilot replies show the retrieved source IDs and whether model or deterministic mode produced the final answer.

Alternative port:

```bash
python -m app.web --port 9000
```

Use a non-loopback host only when you intentionally want to expose the service beyond the local machine.

Local actions are written to `logs/audit.db`; the database is intentionally ignored by Git.