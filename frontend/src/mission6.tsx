import { useMemo, useState } from 'react'
import { Activity, BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Command, Database, PackageCheck, ShieldCheck, TimerReset, X } from 'lucide-react'
import { planTools, type ToolPlan } from './api'

const agentFor=(tool:string)=> tool==='nmap'||tool==='httpx'||tool==='zeek'||tool==='tshark'?'NETWORK ANALYST':tool==='semgrep'||tool==='trivy'||tool==='checkov'||tool==='grype'?'APPSEC ANALYST':tool==='capa'||tool==='radare2'||tool==='yara'?'MALWARE / RE ANALYST':tool==='volatility3'?'DFIR ANALYST':'SPECIALIST AGENT'
const capabilityFor=(tool:string)=> tool==='nmap'?'NETWORK INVENTORY':tool==='httpx'?'HTTP SURFACE':tool==='semgrep'?'SOURCE ANALYSIS':tool==='trivy'||tool==='grype'?'DEPENDENCY AUDIT':tool==='checkov'?'IAC AUDIT':tool==='tshark'||tool==='zeek'?'PACKET ANALYSIS':tool==='volatility3'?'MEMORY ANALYSIS':tool==='capa'?'ARTIFACT CAPABILITIES':tool==='radare2'?'BINARY STRUCTURE':'SPECIALIST ANALYSIS'

export default function MissionControl(){
  const [open,setOpen]=useState(false);const [objective,setObjective]=useState('Investigate suspicious application and network activity');const [plan,setPlan]=useState<ToolPlan>();const [busy,setBusy]=useState(false);const [error,setError]=useState('')
  const build=async()=>{setBusy(true);setError('');try{setPlan(await planTools(objective))}catch(e){setError(String(e))}finally{setBusy(false)}}
  const tools=plan?.required_tools||[]
  const stages=useMemo(()=>[
    {id:'S1',title:'Context & Evidence Review',agent:'MISSION PLANNER',state:'ready'},
    ...tools.map((t,i)=>({id:`S${i+2}`,title:capabilityFor(t.tool_id),agent:agentFor(t.tool_id),state:t.ready?'ready':t.installed?'repair':'blocked'})),
    {id:`S${tools.length+2}`,title:'Evidence Correlation & Counter-Evidence',agent:'CORRELATION AGENT',state:plan?.ready_to_execute?'ready':'waiting'},
    {id:`S${tools.length+3}`,title:'Supervisor Review',agent:'SUPERVISOR AGENT',state:'waiting'},
    {id:`S${tools.length+4}`,title:'Mission Report & Lessons',agent:'REPORTING AGENT',state:'waiting'},
  ],[tools,plan?.ready_to_execute])
  const ready=tools.filter(t=>t.ready).length;const blockers=tools.length-ready;const coverage=tools.length?Math.round((ready/tools.length)*100):0;const confidence=Math.max(48,Math.min(97,62+coverage*.28-blockers*4))
  return <>
    <button className="mission-launch" onClick={()=>setOpen(true)} title="Mission Control"><Command size={15}/><span>MISSION</span></button>
    {open&&<div className="mission-backdrop"><section className="mission-console mission-v7"><header><div><span>PHASE 7 / AI SECURITY OPERATIONS CENTER</span><h2>Mission Operations</h2></div><button onClick={()=>setOpen(false)}><X size={17}/></button></header>
      <div className="mission-objective"><BrainCircuit size={19}/><textarea value={objective} onChange={e=>setObjective(e.target.value)} /><button onClick={build} disabled={busy}>{busy?'PLANNING…':'BUILD OPERATIONS PLAN'}</button></div>
      {error&&<div className="mission-error">{error}</div>}
      <div className="mission-summary"><div><strong>{tools.length}</strong><span>CAPABILITIES</span></div><div><strong>{ready}</strong><span>READY</span></div><div><strong>{blockers}</strong><span>BLOCKERS</span></div><div><strong>{confidence}%</strong><span>SUPERVISOR CONF.</span></div></div>
      <div className="mission-grid mission-grid-v7"><div className="mission-flow"><div className="mission-section-title">MISSION EXECUTION GRAPH</div>{stages.map((s,i)=><div className={`mission-stage ${s.state}`} key={s.id}><span className="stage-id">{s.id}</span><i><CircleDot size={13}/></i><div><strong>{s.title}</strong><small>{s.agent}</small></div><b>{s.state.toUpperCase()}</b>{i<stages.length-1&&<ChevronRight size={13}/>}</div>)}</div>
      <aside className="mission-side"><div className="mission-section-title">CAPABILITY READINESS</div>{tools.length?tools.map(t=><div className="prep-row" key={t.tool_id}><PackageCheck size={14}/><div><strong>{capabilityFor(t.tool_id)}</strong><span>{t.tool_id} · {t.version||'version unavailable'}</span></div><b className={t.ready?'ok':t.installed?'warn':'bad'}>{t.ready?'READY':t.installed?'REPAIR':'MISSING'}</b></div>):<div className="mission-empty">Build a mission plan to inspect prerequisites.</div>}
        <div className="supervisor-card"><div><ShieldCheck size={17}/><strong>SUPERVISOR STATE</strong></div><span>Coverage <b>{coverage}%</b></span><i><em style={{width:`${coverage}%`}}/></i><span>Confidence <b>{confidence}%</b></span><i><em style={{width:`${confidence}%`}}/></i><small>{blockers?`${blockers} prerequisite blocker(s) require preparation.`:'Capability coverage is ready for operator approval.'}</small></div>
        <div className="mission-boundary"><ShieldCheck size={17}/><div><strong>TRUSTED LOCAL WORKER</strong><span>Durable execution remains outside the browser. Registered profiles, scope checks and operator approval are enforced by the mission worker.</span></div></div>
      </aside>
      <div className="mission-v7-lower"><div className="ops-card"><div className="mission-section-title"><Activity size={12}/> AGENT HEALTH</div>{['MISSION PLANNER','APPSEC / NETWORK SPECIALISTS','CORRELATION AGENT','SUPERVISOR AGENT','REPORTING AGENT'].map((a,i)=><div className="agent-health" key={a}><span className={i===0||plan?.ready_to_execute?'on':'idle'}/><strong>{a}</strong><small>{i===0?'READY':plan?.ready_to_execute?'STANDBY':'WAITING'}</small></div>)}</div>
        <div className="ops-card"><div className="mission-section-title"><Database size={12}/> EVIDENCE LANE</div><div className="evidence-lane"><div><b>CONTEXT</b><span>mission objective</span></div>{tools.slice(0,3).map(t=><div key={t.tool_id}><b>{capabilityFor(t.tool_id)}</b><span>{t.ready?'collector ready':'blocked'}</span></div>)}<div><b>REPORT</b><span>awaiting execution</span></div></div></div>
        <div className="ops-card"><div className="mission-section-title"><TimerReset size={12}/> REPLAY / HISTORY</div><div className="history-list"><span><i className="ok"/>Objective received</span><span><i className={plan?'ok':''}/>Capability plan generated</span><span><i className={plan?.ready_to_execute?'ok':''}/>Environment prepared</span><span><i/>Approval pending</span><span><i/>Execution pending</span></div></div></div>
      <div className="mission-command"><span>PHASE 7 OPERATIONS SNAPSHOT</span><code>python scripts/phase7_report.py --mission &lt;MISSION_ID&gt;</code></div>
      <div className="mission-state"><CheckCircle2 size={15}/><span>{plan?.ready_to_execute?'ENVIRONMENT READY FOR OPERATOR APPROVAL':'PREPARATION REQUIRED'}</span></div>
    </section></div>}
  </>
}
