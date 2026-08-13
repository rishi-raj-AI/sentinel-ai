# Sentinel AI

Sentinel AI is a local-first personal AI assistant and digital-forensics automation project.

## Current capabilities

Sentinel now includes a controlled execution pipeline, forensic case/evidence management, SHA-256 and chain-of-custody verification, timeline/correlation, macOS logs, Volatility, PCAP/TShark, YARA, EVTX, Sigma-style detection, an evidence graph, ATT&CK candidate mapping, case reasoning, IOC inventory, tamper-verifiable reports, a local investigation dashboard, an evidence-grounded case copilot, and a read-only autonomous investigation agent.

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
python main.py run "autonomous investigate DFIR-2026-0001 Investigate possible malware infection"
python main.py run "investigation runs DFIR-2026-0001"
```

## Autonomous investigation agent

The agent orchestrates Sentinel's existing analysis engines over evidence already present in a case. It does not acquire evidence, execute commands on endpoints, or autonomously declare a compromise.

Each run records:

- a deterministic investigation plan;
- evidence coverage and collection gaps;
- Sigma/YARA detections;
- network findings;
- ATT&CK candidates;
- evidence-graph statistics;
- three competing hypotheses with confidence percentages;
- grounded and claim-verified Copilot synthesis;
- a timestamped investigation notebook.

Runs are written under `cases/<case-id>/investigations/` as JSON and Markdown files with SHA-256 hashes. Because the run creates notebook artifacts, the CLI asks for modification confirmation even though the forensic analysis itself is read-only.

Use the dedicated web view at:

```text
http://127.0.0.1:8765/agent
```

The agent page supports case selection, investigation objectives, run history, hypothesis ranking, recommendations and notebook inspection.

## Grounded case copilot

The copilot always performs case retrieval before answering. Retrieved sources use explicit IDs such as `EVIDENCE:E0003`, `SIGMA:<rule>`, `YARA:<evidence>:<rule>`, `FLOW:1`, `TIMELINE:42`, and `ATTACK:T1059.001:1`.

Without model configuration Sentinel stays fully usable and returns deterministic evidence-grounded answers. Sentinel also supports a persisted local model configuration and Ollama native `/api/chat`; the local setup can auto-resolve the installed Ollama model name when configuration is stale.

Model answers pass through increasingly strict controls:

1. **Citation grounding** — every Sentinel source ID must come from the retrieved case context; unknown IDs are rejected.
2. **Provenance canonicalization** — malformed evidence aliases are repaired only when they bind exactly to retrieved evidence filename metadata, and every repair is audited.
3. **Claim-level verification** — factual model claims are classified as observed, inferred, recommendation, or limitation and checked against cited source content. Unsupported factual claims are removed. If fewer than 50% of factual claims survive, the entire model synthesis is rejected and Sentinel returns the deterministic grounded fallback.
4. **Source-type-aware entailment** — each source type has bounded evidentiary meaning. Timeline events can prove occurrence but not normality, FLOW records can prove endpoints/protocol/ports but not malware, Sigma/YARA detections can prove rule matches but not compromise unless supporting metadata exists, evidence registration can prove identity/integrity but not maliciousness, and ATT&CK mappings remain behavioral categorization rather than verdicts. Lexical overlap is a secondary sanity check only.

The claim verifier includes explicit guards against common forensic overclaims such as treating validation-only Sigma rules as malware-specific, inferring system updates from YARA match timestamps, calling ordinary timeline activity benign merely because it appears in logs, or asserting confirmed compromise without supporting assessment evidence.

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
