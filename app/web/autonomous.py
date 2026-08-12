from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.forensics.autonomous_investigation import AutonomousInvestigationAgent
from app.forensics.case_manager import CaseManager


class InvestigationRequest(BaseModel):
    objective: str
    max_items: int = 25


def install_autonomous_routes(app: FastAPI, *, cases_root: str = "cases", sigma_rules: str = "rules/sigma") -> None:
    manager = CaseManager(cases_root)

    def agent(case_id: str) -> AutonomousInvestigationAgent:
        manager.load_case(case_id)
        return AutonomousInvestigationAgent(manager.root / case_id, sigma_rules=sigma_rules)

    @app.get("/api/cases/{case_id}/investigations")
    def investigation_runs(case_id: str) -> list[dict[str, Any]]:
        try:
            return agent(case_id).list_runs()
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/investigations/{run_id}")
    def investigation_run(case_id: str, run_id: str) -> dict[str, Any]:
        try:
            return agent(case_id).load_run(run_id)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/cases/{case_id}/investigations")
    def run_investigation(case_id: str, request: InvestigationRequest) -> dict[str, Any]:
        try:
            return agent(case_id).run(request.objective, max_items=max(1, min(request.max_items, 100)), persist=True)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/agent", response_class=HTMLResponse)
    def agent_view() -> str:
        return AGENT_HTML


AGENT_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel AI — Investigation Agent</title><style>
:root{--bg:#071019;--panel:#101b26;--panel2:#142230;--text:#e8f1f8;--muted:#8ba0b2;--line:#243646;--accent:#5eead4;--warn:#fbbf24}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center}.brand{font-weight:800;letter-spacing:.08em}.brand span{color:var(--accent)}main{max-width:1300px;margin:auto;padding:22px}.controls{display:grid;grid-template-columns:260px 1fr auto;gap:10px;margin-bottom:16px}select,input,button{background:#0d1823;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:10px}button{cursor:pointer}button:hover{border-color:var(--accent)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}.wide{grid-column:1/-1}h2{font-size:14px;text-transform:uppercase;letter-spacing:.08em;color:#b9c9d6;margin:0 0 12px}.item{background:var(--panel2);border:1px solid #203544;border-radius:9px;padding:10px;margin:7px 0}.meta{font-size:12px;color:var(--muted);margin-top:5px}.score{font-size:26px;font-weight:800;color:var(--accent)}.step{display:flex;gap:10px;align-items:flex-start}.dot{width:10px;height:10px;border-radius:50%;background:var(--accent);margin-top:5px}.empty{color:var(--muted)}a{color:#7dd3fc}@media(max-width:800px){.grid{grid-template-columns:1fr}.controls{grid-template-columns:1fr}.wide{grid-column:auto}}</style></head>
<body><header><div class="brand">SENTINEL <span>AGENT</span></div><a href="/">Dashboard</a></header><main>
<div class="controls"><select id="case"></select><input id="objective" value="Investigate possible malware infection" placeholder="Investigation objective"><button id="run">Run Investigation</button></div>
<div class="grid"><div class="card"><h2>Run History</h2><div id="history"></div></div><div class="card"><h2>Leading Assessment</h2><div id="assessment" class="empty">Select or run an investigation.</div></div><div class="card"><h2>Competing Hypotheses</h2><div id="hypotheses"></div></div><div class="card"><h2>Recommended Actions</h2><div id="actions"></div></div><div class="card wide"><h2>Investigation Notebook</h2><div id="notebook"></div></div></div>
<script>
const $=id=>document.getElementById(id);let current=null;async function api(p,o){const r=await fetch(p,o);if(!r.ok)throw new Error((await r.json()).detail||r.statusText);return r.json()}const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function cases(){const rows=await api('/api/cases');$('case').innerHTML=rows.map(x=>`<option value="${esc(x.case_id)}">${esc(x.case_id)} — ${esc(x.title||'')}</option>`).join('');current=$('case').value;if(current)await history()}
async function history(){const rows=await api(`/api/cases/${encodeURIComponent(current)}/investigations`);$('history').innerHTML=rows.map(x=>`<div class="item" data-run="${esc(x.run_id)}"><b>${esc(x.objective)}</b><div class="meta">${esc(x.run_id)} · ${esc(x.overall_confidence_percent)}% ${esc(x.overall_confidence)}</div></div>`).join('')||'<div class="empty">No autonomous runs yet.</div>';document.querySelectorAll('[data-run]').forEach(n=>n.onclick=()=>load(n.dataset.run))}
function render(r){$('assessment').innerHTML=`<div class="score">${esc(r.overall_confidence_percent)}%</div><b>${esc(r.leading_hypothesis?.statement||'No leading hypothesis')}</b><div class="meta">${esc(r.overall_confidence)} confidence · ${esc(r.run_id)}</div>`;$('hypotheses').innerHTML=(r.hypotheses||[]).map(h=>`<div class="item"><b>${esc(h.id)} — ${esc(h.confidence_percent)}%</b><div>${esc(h.statement)}</div><div class="meta">${esc(h.confidence)} confidence</div></div>`).join('');$('actions').innerHTML=(r.recommended_actions||[]).map(a=>`<div class="item">${esc(a)}</div>`).join('')||'<div class="empty">No actions.</div>';$('notebook').innerHTML=(r.notebook||[]).map(s=>`<div class="item step"><div class="dot"></div><div><b>${esc(s.step)}</b><div class="meta">${esc(s.timestamp)} · ${esc(s.status)}</div></div></div>`).join('')}
async function load(id){render(await api(`/api/cases/${encodeURIComponent(current)}/investigations/${encodeURIComponent(id)}`))}
$('case').onchange=async e=>{current=e.target.value;await history()};$('run').onclick=async()=>{const obj=$('objective').value.trim();if(!obj)return;$('run').disabled=true;$('run').textContent='Running…';try{const r=await api(`/api/cases/${encodeURIComponent(current)}/investigations`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({objective:obj,max_items:25})});render(r);await history()}catch(e){alert(e.message)}finally{$('run').disabled=false;$('run').textContent='Run Investigation'}};cases();
</script></main></body></html>'''
