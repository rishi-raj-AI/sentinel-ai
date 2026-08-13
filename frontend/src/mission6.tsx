import { useEffect, useMemo, useState } from 'react'
import { Activity, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Command, Database, PackageCheck, ShieldCheck, TimerReset, X } from 'lucide-react'
import { planTools, type ToolPlan } from './api'

const agentFor=(tool:string)=> tool==='nmap'||tool==='httpx'||tool==='zeek'||tool==='tshark'?'NETWORK ANALYST':tool==='semgrep'||tool==='trivy'||tool==='checkov'||tool==='grype'?'APPSEC ANALYST':tool==='capa'||tool==='radare2'||tool==='yara'?'MALWARE / RE ANALYST':tool==='volatility3'?'DFIR ANALYST':'SPECIALIST AGENT'
const capabilityFor=(tool:string)=> tool==='nmap'?'NETWORK INVENTORY':tool==='httpx'?'HTTP SURFACE':tool==='semgrep'?'SOURCE ANALYSIS':tool==='trivy'||tool==='grype'?'DEPENDENCY AUDIT':tool==='checkov'?'IAC AUDIT':tool==='tshark'||tool==='zeek'?'PACKET ANALYSIS':tool==='volatility3'?'MEMORY ANALYSIS':tool==='capa'?'ARTIFACT CAPABILITIES':tool==='radare2'?'BINARY STRUCTURE':'SPECIALIST ANALYSIS'
const OPS_BASE=(import.meta.env.VITE_OPERATIONS_URL||'http://127.0.0.1:8766').replace(/\/$/,'')

type LiveSnapshot={
  mission?:{mission_id?:string;status?:string;approved_by?:string|null;stage_runs?:Array<{stage_id:string;state:string;error?:string|null}>;plan?:{stages?:Array<{stage_id:string;title:string;agent:string}>}}
  events?:Array<{event_id:string;created_at:string;kind:string;actor:string;stage_id?:string|null}>
  evidence?:Array<{evidence_id:string;evidence_type:string;label:string;stage_id?:string|null;confidence?:number|null}>
  supervisor?:{confidence?:number;coverage?:number;contradictions?:number;blockers?:number;verdict?:string;notes?:string[]}
}

export default function MissionControl(){
  const [open,setOpen]=useState(false);const [objective,setObjective]=useState('Investigate suspicious application and network activity');const [plan,setPlan]=useState<ToolPlan>();const [busy,setBusy]=useState(false);const [error,setError]=useState('')
  const [missionId,setMissionId]=useState('');const [live,setLive]=useState<LiveSnapshot>();const [liveError,setLiveError]=useState('');const [liveConnected,setLiveConnected]=useState(false)
  const build=async()=>{setBusy(true);setError('');try{setPlan(await planTools(objective))}catch(e){setError(String(e))}finally{setBusy(false)}}
  const tools=plan?.required_tools||[]
  const stages=useMemo(()=>[
    {id:'S1',title:'Context & Evidence Review',agent:'MISSION PLANNER',state:'ready'},
    ...tools.map((t,i)=>({id:`S${i+2}`,title:capabilityFor(t.tool_id),agent:agentFor(t.tool_id),state:t.ready?'ready':t.installed?'repair':'blocked'})),
    {id:`S${tools.length+2}`,title:'Evidence Correlation & Counter-Evidence',agent:'CORRELATION AGENT',state:plan?.ready_to_execute?'ready':'waiting'},
    {id:`S${tools.length+3}`,title:'Supervisor Review',agent:'SUPERVISOR AGENT',state:'waiting'},
    {id:`S${tools.length+4}`,title:'Mission Report & Lessons',agent:'REPORTING AGENT',state:'waiting'},
  ],[tools,plan?.ready_to_execute])
  useEffect(()=>{
    if(!open||!liveConnected||!missionId.trim()) return
    let cancelled=false
    const pull=async()=>{try{const r=await fetch(`${OPS_BASE}/api/x/operations/missions/${encodeURIComponent(missionId.trim())}`,{headers:{Accept:'application/json'}});if(!r.ok)throw new Error(`${r.status} ${r.statusText}`);const value=await r.json() as LiveSnapshot;if(!cancelled){setLive(value);setLiveError('')}}catch(e){if(!cancelled)setLiveError(String(e))}}
    pull();const id=window.setInterval(pull,1500);return()=>{cancelled=true;window.clearInterval(id)}
  },[open,liveConnected,missionId])
  const runMap=new Map((live?.mission?.stage_runs||[]).map(r=>[r.stage_id,r.state]));const liveStages=(live?.mission?.plan?.stages||[]).map(s=>({...s,state:runMap.get(s.stage_id)||'waiting'}))
  const ready=tools.filter(t=>t.ready).length;const blockers=tools.length-ready;const plannedCoverage=tools.length?Math.round((ready/tools.length)*100):0;const coverage=live?.supervisor?.coverage!=null?Math.round(live.supervisor.coverage*100):plannedCoverage;const confidence=live?.supervisor?.confidence!=null?Math.round(live.supervisor.confidence*100):Math.max(48,Math.min(97,62+plannedCoverage*.28-blockers*4))
  const displayStages=liveStages.length?liveStages:stages
  return <>
    <button className="mission-launch" onClick={()=>setOpen(true)} title="Mission Control"><Command size={15}/><span>MISSION</span></button>
    {open&&<div className="mission-backdrop"><section className="mission-console mission-v7"><header><div><span>PHASE 7.2 / REAL-TIME SECURITY OPERATIONS CENTER</span><h2>Mission Operations</h2></div><button onClick={()=>setOpen(false)}><X size={17}/></button></header>
      <div className="mission-objective"><BrainCircuit size={19}/><textarea value={objective} onChange={e=>setObjective(e.target.value)} /><button onClick={build} disabled={busy}>{busy?'PLANNING…':'BUILD OPERATIONS PLAN'}</button></div>
      <div className="mission-live-connect"><input value={missionId} onChange={e=>setMissionId(e.target.value.toUpperCase())} placeholder="MISSION ID  e.g. M-XXXXXXXXXX"/><button onClick={()=>setLiveConnected(v=>!v)}>{liveConnected?'DISCONNECT LIVE':'CONNECT LIVE'}</button><span className={liveConnected&&!liveError?'live':'idle'}>{liveConnected&&!liveError?'LIVE TELEMETRY':'OFFLINE'}</span></div>
      {(error||liveError)&&<div className="mission-error">{error||liveError}</div>}
      <div className="mission-summary"><div><strong>{live?.mission?.status?.toUpperCase()||tools.length}</strong><span>{live?'MISSION STATE':'CAPABILITIES'}</span></div><div><strong>{live?.evidence?.length??ready}</strong><span>{live?'EVIDENCE':'READY'}</span></div><div><strong>{live?.supervisor?.blockers??blockers}</strong><span>BLOCKERS</span></div><div><strong>{confidence}%</strong><span>SUPERVISOR CONF.</span></div></div>
      <div className="mission-grid mission-grid-v7"><div className="mission-flow"><div className="mission-section-title">MISSION EXECUTION GRAPH</div>{displayStages.map((s:any,i)=><div className={`mission-stage ${s.state}`} key={s.stage_id||s.id}><span className="stage-id">{s.stage_id||s.id}</span><i><CircleDot size={13}/></i><div><strong>{s.title}</strong><small>{s.agent}</small></div><b>{String(s.state).toUpperCase()}</b>{i<displayStages.length-1&&<ChevronRight size={13}/>}</div>)}</div>
      <aside className="mission-side"><div className="mission-section-title">CAPABILITY READINESS</div>{tools.length?tools.map(t=><div className="prep-row" key={t.tool_id}><PackageCheck size={14}/><div><strong>{capabilityFor(t.tool_id)}</strong><span>{t.tool_id} · {t.version||'version unavailable'}</span></div><b className={t.ready?'ok':t.installed?'warn':'bad'}>{t.ready?'READY':t.installed?'REPAIR':'MISSING'}</b></div>):<div className="mission-empty">Build a mission plan to inspect prerequisites.</div>}
        <div className="supervisor-card"><div><ShieldCheck size={17}/><strong>SUPERVISOR STATE</strong></div><span>Coverage <b>{coverage}%</b></span><i><em style={{width:`${coverage}%`}}/></i><span>Confidence <b>{confidence}%</b></span><i><em style={{width:`${confidence}%`}}/></i><small>{live?.supervisor?.verdict||((live?.supervisor?.blockers??blockers)?'Prerequisites or mission stages require attention.':'Capability coverage is ready for operator approval.')}</small></div>
        <div className="mission-boundary"><ShieldCheck size={17}/><div><strong>READ-ONLY LIVE TELEMETRY</strong><span>Mission Control observes durable worker state only. Execution remains outside the browser and stays governed by the trusted mission worker.</span></div></div>
      </aside>
      <div className="mission-v7-lower"><div className="ops-card"><div className="mission-section-title"><Activity size={12}/> AGENT HEALTH</div>{(liveStages.length?liveStages.map(s=>s.agent):['MISSION PLANNER','APPSEC / NETWORK SPECIALISTS','CORRELATION AGENT','SUPERVISOR AGENT','REPORTING AGENT']).slice(0,6).map((a,i)=><div className="agent-health" key={`${a}-${i}`}><span className={liveStages.length&&liveStages[i]?.state==='completed'?'on':i===0||plan?.ready_to_execute?'on':'idle'}/><strong>{a}</strong><small>{liveStages.length?String(liveStages[i]?.state||'waiting').toUpperCase():i===0?'READY':plan?.ready_to_execute?'STANDBY':'WAITING'}</small></div>)}</div>
        <div className="ops-card"><div className="mission-section-title"><Database size={12}/> EVIDENCE LANE</div><div className="evidence-lane">{live?.evidence?.length?live.evidence.slice(-5).map(e=><div key={e.evidence_id}><b>{e.evidence_type.toUpperCase()}</b><span>{e.label}</span></div>):<><div><b>CONTEXT</b><span>mission objective</span></div>{tools.slice(0,3).map(t=><div key={t.tool_id}><b>{capabilityFor(t.tool_id)}</b><span>{t.ready?'collector ready':'blocked'}</span></div>)}<div><b>REPORT</b><span>awaiting execution</span></div></>}</div></div>
        <div className="ops-card"><div className="mission-section-title"><TimerReset size={12}/> REPLAY / HISTORY</div><div className="history-list">{live?.events?.length?live.events.slice(-6).reverse().map(e=><span key={e.event_id}><i className="ok"/><b>{e.kind}</b><small>{e.actor}{e.stage_id?` · ${e.stage_id}`:''}</small></span>):<><span><i className="ok"/>Objective received</span><span><i className={plan?'ok':''}/>Capability plan generated</span><span><i className={plan?.ready_to_execute?'ok':''}/>Environment prepared</span><span><i/>Approval pending</span><span><i/>Execution pending</span></>}</div></div></div>
      <div className="mission-command"><span>MISSION TELEMETRY SERVICE</span><code>python scripts/phase7_stream_server.py</code></div>
      <div className="mission-state"><CheckCircle2 size={15}/><span>{liveConnected&&!liveError?'LIVE MISSION STATE SYNCHRONIZED':plan?.ready_to_execute?'ENVIRONMENT READY FOR OPERATOR APPROVAL':'PREPARATION REQUIRED'}</span></div>
      </div>
    </section></div>}
  </>
}
