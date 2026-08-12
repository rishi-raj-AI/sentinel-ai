#!/usr/bin/env bash
set -euo pipefail

MODEL="${1:-llama3.2}"
CASE_ID="${2:-DFIR-2026-0001}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

log(){ printf '[sentinel-model-setup] %s\n' "$*"; }
fail(){ printf '[sentinel-model-setup] ERROR: %s\n' "$*" >&2; exit 1; }

command -v brew >/dev/null 2>&1 || fail "Homebrew is required. Install Homebrew first, then rerun this script."

if ! command -v ollama >/dev/null 2>&1; then
  log "Ollama not found; installing with Homebrew..."
  brew install ollama
else
  log "Ollama already installed: $(ollama --version 2>/dev/null || true)"
fi

mkdir -p logs config

if ! curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  log "Starting Ollama server on 127.0.0.1:11434..."
  nohup ollama serve > logs/ollama-server.log 2>&1 &
  OLLAMA_PID=$!
  ready=0
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    kill "$OLLAMA_PID" >/dev/null 2>&1 || true
    fail "Ollama server did not become ready. See logs/ollama-server.log"
  fi
else
  log "Ollama server is already reachable."
fi

log "Pulling model: $MODEL"
ollama pull "$MODEL"

cat > config/model.json <<EOF
{
  "endpoint": "http://127.0.0.1:11434/v1/chat/completions",
  "model": "$MODEL",
  "api_key": "",
  "timeout": 60
}
EOF

log "Testing OpenAI-compatible endpoint..."
python - "$MODEL" <<'PY'
import json, sys
import httpx
model = sys.argv[1]
payload = {
    "model": model,
    "messages": [{"role": "user", "content": "Reply exactly with SENTINEL MODEL ONLINE"}],
    "temperature": 0,
}
r = httpx.post("http://127.0.0.1:11434/v1/chat/completions", json=payload, timeout=60)
r.raise_for_status()
body = r.json()
text = (((body.get("choices") or [{}])[0].get("message") or {}).get("content") or "").strip()
if not text:
    raise SystemExit("Model endpoint returned no text")
print(text)
PY

log "Checking Sentinel provider status..."
unset SENTINEL_MODEL_ENDPOINT SENTINEL_MODEL_NAME SENTINEL_MODEL_API_KEY || true
python main.py run "copilot status"

if [ -d "cases/$CASE_ID" ]; then
  log "Running grounded Sentinel copilot validation against $CASE_ID..."
  python main.py run "copilot ask $CASE_ID Why is UDP port 4444 worth reviewing?"
else
  log "Case $CASE_ID not found; skipping case-specific copilot validation."
fi

log "Setup complete. Sentinel will persistently use config/model.json."
log "Start the dashboard with: python -m app.web"
