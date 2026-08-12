from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from app.forensics.attack_mapping import AttackMappingEngine
from app.forensics.case_copilot import CaseCopilot, ModelProvider
from app.forensics.case_manager import CaseManager
from app.forensics.case_reasoning import CaseReasoningEngine
from app.forensics.evidence_graph import EvidenceGraphEngine
from app.forensics.network_intelligence import NetworkIntelligenceEngine
from app.forensics.sigma_engine import SigmaEngine
from app.forensics.threat_intel import ThreatIntelEngine
from app.forensics.timeline import TimelineStore


class ChatRequest(BaseModel):
    question: str


class DashboardService:
    """Read-only aggregation layer for the local investigation dashboard."""

    def __init__(self, cases_root: str = "cases", sigma_rules: str = "rules/sigma", provider: ModelProvider | None = None) -> None:
        self.manager = CaseManager(cases_root)
        self.sigma_rules = sigma_rules
        self.provider = provider or ModelProvider()

    def _case_dir(self, case_id: str) -> Path:
        self.manager.load_case(case_id)
        return self.manager.root / case_id

    def list_cases(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        if not self.manager.root.exists():
            return rows
        for item in sorted(self.manager.root.iterdir(), reverse=True):
            path = item / "case.json"
            if not path.is_file():
                continue
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rows.append({
                "case_id": record.get("case_id", item.name),
                "title": record.get("title"),
                "status": record.get("status"),
                "created_at": record.get("created_at"),
                "evidence_count": len(record.get("evidence", [])),
            })
        return rows

    def copilot_status(self) -> dict[str, Any]:
        return {
            "configured": self.provider.configured,
            "mode": "model" if self.provider.configured else "deterministic",
            "model": self.provider.model or None,
            "endpoint_configured": bool(self.provider.endpoint),
            "grounding": "case-retrieval-required",
        }

    def overview(self, case_id: str, max_items: int = 20) -> dict[str, Any]:
        case_dir = self._case_dir(case_id)
        record = self.manager.load_case(case_id)
        timeline = TimelineStore(case_dir).read()
        brief = CaseReasoningEngine(case_dir, sigma_rules=self.sigma_rules).build(max_items=max_items)
        sigma = SigmaEngine(case_dir).analyze(self.sigma_rules, max_detections=max_items)
        attack = AttackMappingEngine(case_dir).analyze(max_candidates=max_items)
        network = NetworkIntelligenceEngine(case_dir).analyze(max_flows=max_items)
        graph = EvidenceGraphEngine(case_dir).build(max_nodes=3000, max_edges=6000)
        intel = ThreatIntelEngine(case_dir).inventory(max_items=max_items)
        source_counts = Counter(str(row.get("source") or "unknown") for row in timeline)
        type_counts = Counter(str(row.get("event_type") or "unknown") for row in timeline)
        return {
            "case": record,
            "brief": brief,
            "stats": {
                "events": len(timeline),
                "evidence": len(record.get("evidence", [])),
                "sigma_detections": sigma.get("detection_count", 0),
                "attack_candidates": attack.get("candidate_count", 0),
                "graph_nodes": graph.get("node_count", 0),
                "graph_edges": graph.get("edge_count", 0),
                "sources": dict(source_counts),
                "event_types": dict(type_counts),
            },
            "evidence": record.get("evidence", []),
            "sigma": sigma,
            "attack": attack,
            "network": network,
            "threat_intel": intel,
            "reports": self.reports(case_id),
            "copilot": self.copilot_status(),
        }

    def timeline(self, case_id: str, limit: int = 250, source: str | None = None, event_type: str | None = None) -> dict[str, Any]:
        case_dir = self._case_dir(case_id)
        rows = TimelineStore(case_dir).read()
        if source:
            rows = [row for row in rows if str(row.get("source")) == source]
        if event_type:
            rows = [row for row in rows if str(row.get("event_type")) == event_type]
        total = len(rows)
        rows = rows[-limit:]
        return {"total": total, "returned": len(rows), "events": list(reversed(rows))}

    def graph(self, case_id: str, max_nodes: int = 120, max_edges: int = 240) -> dict[str, Any]:
        case_dir = self._case_dir(case_id)
        return EvidenceGraphEngine(case_dir).build(max_nodes=max_nodes, max_edges=max_edges)

    def detections(self, case_id: str, max_items: int = 100) -> dict[str, Any]:
        case_dir = self._case_dir(case_id)
        sigma = SigmaEngine(case_dir).analyze(self.sigma_rules, max_detections=max_items)
        events = TimelineStore(case_dir).read()
        yara: dict[tuple[str, str], dict[str, Any]] = {}
        for event in events:
            if event.get("source") != "yara" and event.get("event_type") != "yara_match":
                continue
            details = event.get("details") or {}
            key = (str(event.get("evidence_id") or ""), str(details.get("rule") or "unknown"))
            row = yara.setdefault(key, {
                "evidence_id": event.get("evidence_id"),
                "rule": details.get("rule"),
                "match_count": 0,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
            })
            row["match_count"] += 1
            stamp = event.get("timestamp")
            if stamp and (not row["first_seen"] or stamp < row["first_seen"]):
                row["first_seen"] = stamp
            if stamp and (not row["last_seen"] or stamp > row["last_seen"]):
                row["last_seen"] = stamp
        return {"sigma": sigma, "yara": list(yara.values())[:max_items]}

    def reports(self, case_id: str) -> list[dict[str, Any]]:
        case_dir = self._case_dir(case_id)
        reports_dir = case_dir / "reports"
        if not reports_dir.exists():
            return []
        rows: list[dict[str, Any]] = []
        for path in sorted(reports_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if not path.is_file():
                continue
            rows.append({"name": path.name, "size_bytes": path.stat().st_size, "suffix": path.suffix.lower()})
        return rows

    def report_path(self, case_id: str, filename: str) -> Path:
        case_dir = self._case_dir(case_id)
        reports_dir = (case_dir / "reports").resolve()
        target = (reports_dir / filename).resolve()
        if reports_dir not in target.parents or not target.is_file():
            raise FileNotFoundError(filename)
        return target

    def chat(self, case_id: str, question: str) -> dict[str, Any]:
        case_dir = self._case_dir(case_id)
        return CaseCopilot(case_dir, sigma_rules=self.sigma_rules, provider=self.provider).answer(question, max_sources=12)


def create_dashboard_app(cases_root: str = "cases", sigma_rules: str = "rules/sigma", provider: ModelProvider | None = None) -> FastAPI:
    service = DashboardService(cases_root=cases_root, sigma_rules=sigma_rules, provider=provider)
    app = FastAPI(title="Sentinel AI Investigation Dashboard", docs_url="/api/docs", redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return DASHBOARD_HTML

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "mode": "local-read-only-dashboard", "copilot": service.copilot_status()}

    @app.get("/api/copilot/status")
    def copilot_status() -> dict[str, Any]:
        return service.copilot_status()

    @app.get("/api/cases")
    def cases() -> list[dict[str, Any]]:
        return service.list_cases()

    @app.get("/api/cases/{case_id}/overview")
    def overview(case_id: str, max_items: int = Query(20, ge=1, le=100)) -> dict[str, Any]:
        try:
            return service.overview(case_id, max_items=max_items)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/timeline")
    def timeline(case_id: str, limit: int = Query(250, ge=1, le=2000), source: str | None = None, event_type: str | None = None) -> dict[str, Any]:
        try:
            return service.timeline(case_id, limit=limit, source=source, event_type=event_type)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/graph")
    def graph(case_id: str, max_nodes: int = Query(120, ge=1, le=500), max_edges: int = Query(240, ge=1, le=1000)) -> dict[str, Any]:
        try:
            return service.graph(case_id, max_nodes=max_nodes, max_edges=max_edges)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/detections")
    def detections(case_id: str, max_items: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
        try:
            return service.detections(case_id, max_items=max_items)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/reports")
    def reports(case_id: str) -> list[dict[str, Any]]:
        try:
            return service.reports(case_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/api/cases/{case_id}/reports/{filename:path}")
    def report_file(case_id: str, filename: str):
        try:
            path = service.report_path(case_id, filename)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=404, detail="Report not found") from exc
        return FileResponse(path)

    @app.post("/api/cases/{case_id}/chat")
    def chat(case_id: str, request: ChatRequest) -> dict[str, Any]:
        try:
            return service.chat(case_id, request.question)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app


DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel AI — Investigation Dashboard</title>
<style>
:root{--bg:#081018;--panel:#101b26;--panel2:#142230;--text:#e8f1f8;--muted:#8ba0b2;--line:#243646;--accent:#5eead4;--warn:#fbbf24;--high:#fb7185;--blue:#60a5fa}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(160deg,#071019,#0b1622 55%,#071019);color:var(--text);font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh}
header{height:68px;border-bottom:1px solid var(--line);display:flex;align-items:center;padding:0 24px;gap:18px;background:rgba(8,16,24,.92);position:sticky;top:0;z-index:10;backdrop-filter:blur(12px)}
.brand{font-weight:800;letter-spacing:.09em}.brand span{color:var(--accent)}select,input,button{background:#0d1823;color:var(--text);border:1px solid var(--line);border-radius:8px;padding:9px 11px}button{cursor:pointer}button:hover{border-color:var(--accent)}#caseSelect{min-width:270px;margin-left:auto}
main{padding:22px;max-width:1600px;margin:auto}.hero{display:flex;gap:20px;align-items:flex-start;margin-bottom:18px}.hero h1{margin:0;font-size:28px}.hero p{margin:8px 0 0;color:var(--muted)}.badge{padding:5px 9px;border-radius:999px;background:#173246;color:#9bd8ff;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.card{background:rgba(16,27,38,.94);border:1px solid var(--line);border-radius:13px;padding:16px;overflow:hidden}.metric{grid-column:span 2}.metric b{font-size:28px;display:block;margin-top:6px}.metric span{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.summary{grid-column:span 6}.actions{grid-column:span 6}.evidence{grid-column:span 5}.detections{grid-column:span 7}.timeline{grid-column:span 7}.graph{grid-column:span 5}.reports{grid-column:span 5}.chat{grid-column:span 7}.card h2{font-size:15px;margin:0 0 12px;text-transform:uppercase;letter-spacing:.08em;color:#b9c9d6}.assessment{font-size:21px;font-weight:700}.confidence{color:var(--accent);font-size:13px;margin-top:5px}.list{display:flex;flex-direction:column;gap:8px}.item{background:var(--panel2);border:1px solid #203544;border-radius:9px;padding:10px}.item .meta{color:var(--muted);font-size:12px;margin-top:5px}.sev-high{border-left:3px solid var(--high)}.sev-medium{border-left:3px solid var(--warn)}.sev-low{border-left:3px solid var(--blue)}
table{width:100%;border-collapse:collapse;font-size:12px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:8px;vertical-align:top}th{color:var(--muted);font-weight:600}code{font-size:11px;color:#a7f3d0}.scroll{max-height:390px;overflow:auto}.tabs{display:flex;gap:7px;margin-bottom:10px}.tab{font-size:12px;padding:6px 9px}.tab.active{border-color:var(--accent);color:var(--accent)}
#graphSvg{width:100%;height:390px;background:#0b1520;border-radius:9px;border:1px solid var(--line)}.chatlog{height:315px;overflow:auto;padding:4px;display:flex;flex-direction:column;gap:8px}.msg{max-width:92%;padding:9px 11px;border-radius:10px;line-height:1.4;font-size:13px;white-space:pre-wrap}.user{align-self:flex-end;background:#173a4d}.assistant{align-self:flex-start;background:#152532;border:1px solid #264052}.chatbox{display:flex;gap:8px;margin-top:10px}.chatbox input{flex:1}.small{font-size:12px;color:var(--muted)}.sourcechips{display:flex;flex-wrap:wrap;gap:4px;margin-top:7px}.sourcechip{font-size:10px;padding:3px 5px;border-radius:5px;background:#0b1821;color:#8bd5ff;border:1px solid #294254}.mode{color:var(--accent);font-size:10px;margin-top:6px}a{color:#7dd3fc;text-decoration:none}a:hover{text-decoration:underline}.empty{color:var(--muted);font-size:13px}.loading{opacity:.55;pointer-events:none}
@media(max-width:1000px){.metric{grid-column:span 4}.summary,.actions,.evidence,.detections,.timeline,.graph,.reports,.chat{grid-column:1/-1}}@media(max-width:620px){.metric{grid-column:span 6}header{padding:0 12px}.brand{font-size:13px}#caseSelect{min-width:150px}main{padding:12px}}
</style></head><body>
<header><div class="brand">SENTINEL <span>AI</span></div><div class="badge">LOCAL DFIR</div><select id="caseSelect"></select><button id="refreshBtn">Refresh</button></header>
<main id="app"><div class="hero"><div><h1 id="caseTitle">Investigation Dashboard</h1><p id="caseMeta">Loading cases…</p></div></div>
<div class="grid">
<div class="card metric"><span>Events</span><b id="mEvents">—</b></div><div class="card metric"><span>Evidence</span><b id="mEvidence">—</b></div><div class="card metric"><span>Sigma</span><b id="mSigma">—</b></div><div class="card metric"><span>ATT&CK</span><b id="mAttack">—</b></div><div class="card metric"><span>Graph Nodes</span><b id="mNodes">—</b></div><div class="card metric"><span>Graph Edges</span><b id="mEdges">—</b></div>
<div class="card summary"><h2>Assessment</h2><div class="assessment" id="assessment">—</div><div class="confidence" id="confidence"></div><div class="list" id="observations" style="margin-top:12px"></div></div>
<div class="card actions"><h2>Recommended Actions & Gaps</h2><div class="list" id="actions"></div></div>
<div class="card evidence"><h2>Evidence Inventory</h2><div class="scroll"><table><thead><tr><th>ID</th><th>File</th><th>Size</th><th>SHA-256</th></tr></thead><tbody id="evidenceRows"></tbody></table></div></div>
<div class="card detections"><h2>Detections</h2><div class="tabs"><button class="tab active" data-det="sigma">Sigma</button><button class="tab" data-det="yara">YARA</button></div><div class="scroll list" id="detectionList"></div></div>
<div class="card timeline"><h2>Timeline</h2><div class="scroll"><table><thead><tr><th>Time</th><th>Source</th><th>Type</th><th>Summary</th><th>Evidence</th></tr></thead><tbody id="timelineRows"></tbody></table></div></div>
<div class="card graph"><h2>Evidence Graph</h2><div class="small" id="graphMeta"></div><svg id="graphSvg" viewBox="0 0 640 390"></svg></div>
<div class="card reports"><h2>Reports</h2><div class="list" id="reportList"></div></div>
<div class="card chat"><h2>Investigator Copilot</h2><div class="small" id="copilotStatus">Evidence-grounded read-only case assistant.</div><div class="chatlog" id="chatLog"><div class="msg assistant">Ask a natural-language question. Sentinel retrieves supporting case sources before answering.</div></div><form class="chatbox" id="chatForm"><input id="chatInput" autocomplete="off" placeholder="Why is UDP/4444 worth reviewing?"><button>Ask</button></form></div>
</div></main>
<script>
let currentCase=null, overview=null, detections=null, activeDet='sigma';
const $=id=>document.getElementById(id); const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path,opts){const r=await fetch(path,opts);if(!r.ok)throw new Error((await r.json()).detail||r.statusText);return r.json()}
function size(n){if(n==null)return '—';if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(1)+' KB';return (n/1048576).toFixed(1)+' MB'}
function sevClass(s){return 'sev-'+(['high','medium','low'].includes(String(s).toLowerCase())?String(s).toLowerCase():'low')}
async function loadCases(){const rows=await api('/api/cases');$('caseSelect').innerHTML=rows.map(r=>`<option value="${esc(r.case_id)}">${esc(r.case_id)} — ${esc(r.title||'Untitled')}</option>`).join('');if(rows.length){currentCase=$('caseSelect').value;await loadCase()}else{$('caseMeta').textContent='No cases found.'}}
async function loadCase(){if(!currentCase)return;$('app').classList.add('loading');try{[overview,detections]=await Promise.all([api(`/api/cases/${encodeURIComponent(currentCase)}/overview`),api(`/api/cases/${encodeURIComponent(currentCase)}/detections`)]);renderOverview();await Promise.all([renderTimeline(),renderGraph()]);renderDetections();}catch(e){alert(e.message)}finally{$('app').classList.remove('loading')}}
function renderOverview(){const c=overview.case,b=overview.brief,s=overview.stats;$('caseTitle').textContent=c.title||c.case_id;$('caseMeta').textContent=`${c.case_id} · ${c.status||'unknown'} · created ${c.created_at||'—'}`;$('mEvents').textContent=s.events;$('mEvidence').textContent=s.evidence;$('mSigma').textContent=s.sigma_detections;$('mAttack').textContent=s.attack_candidates;$('mNodes').textContent=s.graph_nodes;$('mEdges').textContent=s.graph_edges;$('assessment').textContent=b.headline;$('confidence').textContent=`Confidence: ${b.confidence}`;const cp=overview.copilot||{};$('copilotStatus').textContent=cp.configured?`Model-backed · ${cp.model||'configured model'} · evidence grounding required`:'Deterministic grounding active · configure a model endpoint for model-backed synthesis';$('observations').innerHTML=(b.observations||[]).slice(0,6).map(x=>`<div class="item ${sevClass(x.severity)}"><b>${esc(x.title)}</b><div class="meta">${esc(x.basis)} · ${esc(x.evidence_id||'no evidence id')}</div></div>`).join('')||'<div class="empty">No observations.</div>';
let a=[...(b.recommended_actions||[]).map(x=>({t:'Action',v:x})),...(b.collection_gaps||[]).map(x=>({t:'Gap',v:x}))];$('actions').innerHTML=a.slice(0,10).map(x=>`<div class="item"><b>${esc(x.t)}</b><div class="meta">${esc(x.v)}</div></div>`).join('')||'<div class="empty">No outstanding actions.</div>';
$('evidenceRows').innerHTML=(overview.evidence||[]).map(x=>`<tr><td>${esc(x.evidence_id)}</td><td>${esc(x.filename)}</td><td>${size(x.size_bytes)}</td><td><code>${esc((x.sha256||'').slice(0,16))}…</code></td></tr>`).join('');$('reportList').innerHTML=(overview.reports||[]).map(r=>`<div class="item"><a target="_blank" href="/api/cases/${encodeURIComponent(currentCase)}/reports/${encodeURIComponent(r.name)}">${esc(r.name)}</a><div class="meta">${size(r.size_bytes)}</div></div>`).join('')||'<div class="empty">No reports exported yet.</div>'}
function renderDetections(){let rows=activeDet==='sigma'?(detections.sigma?.detections||[]):(detections.yara||[]);if(activeDet==='sigma')$('detectionList').innerHTML=rows.map(x=>`<div class="item ${sevClass(x.level)}"><b>${esc(x.title)}</b><div class="meta">${esc(x.rule_id)} · ${esc(x.evidence_id||'—')} · ${esc(x.level||'')}</div></div>`).join('')||'<div class="empty">No Sigma detections.</div>';else $('detectionList').innerHTML=rows.map(x=>`<div class="item sev-medium"><b>${esc(x.rule)}</b><div class="meta">${esc(x.evidence_id||'—')} · matches ${esc(x.match_count)} · ${esc(x.first_seen||'')}</div></div>`).join('')||'<div class="empty">No YARA matches.</div>'}
async function renderTimeline(){const d=await api(`/api/cases/${encodeURIComponent(currentCase)}/timeline?limit=250`);$('timelineRows').innerHTML=d.events.map(x=>`<tr><td>${esc((x.timestamp||'').replace('T',' ').slice(0,19))}</td><td>${esc(x.source)}</td><td>${esc(x.event_type)}</td><td>${esc(x.summary)}</td><td>${esc(x.evidence_id||'—')}</td></tr>`).join('')}
async function renderGraph(){const g=await api(`/api/cases/${encodeURIComponent(currentCase)}/graph?max_nodes=120&max_edges=240`);$('graphMeta').textContent=`Showing ${g.node_count} nodes / ${g.edge_count} edges`;
const svg=$('graphSvg');svg.innerHTML='';const nodes=g.nodes||[], edges=g.edges||[], W=640,H=390,cx=W/2,cy=H/2,R=Math.min(W,H)*.39;const pos=new Map();nodes.forEach((n,i)=>{const a=(Math.PI*2*i/Math.max(nodes.length,1))+(i%7)*.035;const ring=.35+.65*((i%17)/16);pos.set(n.id,[cx+Math.cos(a)*R*ring,cy+Math.sin(a)*R*ring])});
const ns='http://www.w3.org/2000/svg';edges.forEach(e=>{const a=pos.get(e.source),b=pos.get(e.target);if(!a||!b)return;const l=document.createElementNS(ns,'line');l.setAttribute('x1',a[0]);l.setAttribute('y1',a[1]);l.setAttribute('x2',b[0]);l.setAttribute('y2',b[1]);l.setAttribute('stroke','#294254');l.setAttribute('stroke-width','.7');svg.appendChild(l)});nodes.forEach(n=>{const p=pos.get(n.id),c=document.createElementNS(ns,'circle');c.setAttribute('cx',p[0]);c.setAttribute('cy',p[1]);c.setAttribute('r',n.type==='evidence'?5:n.type==='detection'?4.5:3);c.setAttribute('fill',n.type==='evidence'?'#5eead4':n.type==='detection'?'#fbbf24':n.type==='process'?'#60a5fa':'#8ba0b2');const t=document.createElementNS(ns,'title');t.textContent=`${n.type}: ${n.label}`;c.appendChild(t);svg.appendChild(c)})}
$('caseSelect').addEventListener('change',async e=>{currentCase=e.target.value;await loadCase()});$('refreshBtn').addEventListener('click',loadCase);document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');activeDet=b.dataset.det;renderDetections()});
$('chatForm').addEventListener('submit',async e=>{e.preventDefault();const input=$('chatInput'),q=input.value.trim();if(!q||!currentCase)return;const log=$('chatLog');log.insertAdjacentHTML('beforeend',`<div class="msg user">${esc(q)}</div>`);input.value='';try{const r=await api(`/api/cases/${encodeURIComponent(currentCase)}/chat`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:q})});const chips=(r.sources||[]).slice(0,12).map(s=>`<span class="sourcechip" title="${esc(s.title||'')}">${esc(s.source_id||s.kind||'source')}</span>`).join('');const mode=r.mode==='model'?`Model: ${esc(r.model||'configured')}`:'Deterministic grounded fallback';log.insertAdjacentHTML('beforeend',`<div class="msg assistant">${esc(r.answer)}<div class="sourcechips">${chips}</div><div class="mode">${mode} · ${esc(r.source_count||0)} sources</div></div>`)}catch(err){log.insertAdjacentHTML('beforeend',`<div class="msg assistant">Error: ${esc(err.message)}</div>`)}log.scrollTop=log.scrollHeight});
loadCases();
</script></body></html>'''