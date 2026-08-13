import { useState } from 'react'
import { BrainCircuit, CheckCircle2, ChevronRight, CircleDot, Command, PackageCheck, ShieldCheck, X } from 'lucide-react'
import { planTools, type ToolPlan } from './api'

const agentFor=(tool:string)=> tool==='nmap'||tool==='httpx'||tool==='zeek'||tool==='tshark'?'NETWORK ANALYST':tool==='semgrep'||tool==='trivy'||tool==='checkov'?'APPSEC ANALYST':tool==='capa'||tool==='radare2'||tool==='yara'?'MALWARE / RE ANALYST':tool==='volatility3'?'DFIR ANALYST':'SPECIALIST AGENT'

export default function MissionControl(){
  const [open,setOpen]=useState(false);const [objective,setObjective]=useState('Investigate suspicious application and network activity');const [plan,setPlan]=useState<ToolPlan>();const [busy,setBusy]=useState(false);const [error,setError]=useState('')
  const build=async()=>{setBusy(true);setError('');try{setPlan(await planTools(objective))}catch(e){setError(String(e))}finally{setBusy(false)}}
  const tools=plan?.required_tools||[]
  const stages=[
    {id:'S1',title:'Context & Evidence Review',agent:'MISSION PLANNER',state:'ready'},
    ...tools.map((t,i)=>({id:`S${i+2}`,title:t.reason,agent:agentFor(t.tool_id),state:t.ready?'ready':t.installed?'repair':'blocked'})),
    {id:`S${tools.length+2}`,title:'Evidence Correlation & Counter-Evidence',agent:'CORRELATION AGENT',state:plan?.ready_to_execute?'ready':'waiting'},
    {id:`S${tools.length+3}`,title:'Supervisor Review',agent:'SUPERVISOR AGENT',state:'waiting'},
    {id:`S${tools.length+4}`,title:'Mission Report & Lessons',agent:'REPORTING AGENT',state:'waiting'},
  ]
  return <>
    <button className="mission-launch" onClick={()=>setOpen(true)} title="Mission Control"><Command size={15}/><span>MISSION</span></button>
    {open&&<div className="mission-backdrop"><section className="mission-console"><header><div><span>PHASE 6 / AUTONOMY SUPERVISOR</span><h2>Mission Control</h2></div><button onClick={()=>setOpen(false)}><X size={17}/></button></header>
      <div className="mission-objective"><BrainCircuit size={19}/><textarea value={objective} onChange={e=>setObjective(e.target.value)} /><button onClick={build} disabled={busy}>{busy?'PLANNING…':'BUILD MISSION PLAN'}</button></div>
      {error&&<div className="mission-error">{error}</div>}
      <div className="mission-summary"><div><strong>{tools.length}</strong><span>CAPABILITIES</span></div><div><strong>{tools.filter(t=>t.ready).length}</strong><span>READY</span></div><div><strong>{tools.filter(t=>!t.ready).length}</strong><span>BLOCKERS</span></div><div><strong>{stages.length}</strong><span>STAGES</span></div></div>
      <div className="mission-grid"><div className="mission-flow"><div className="mission-section-title">EXECUTION GRAPH</div>{stages.map((s,i)=><div className={`mission-stage ${s.state}`} key={s.id}><span className="stage-id">{s.id}</span><i><CircleDot size={13}/></i><div><strong>{s.title}</strong><small>{s.agent}</small></div><b>{s.state.toUpperCase()}</b>{i<stages.length-1&&<ChevronRight size={13}/>}</div>)}</div>
      <aside className="mission-side"><div className="mission-section-title">PREPARATION</div>{tools.length?tools.map(t=><div className="prep-row" key={t.tool_id}><PackageCheck size={14}/><div><strong>{t.tool_id}</strong><span>{t.version||'version unavailable'}</span></div><b className={t.ready?'ok':t.installed?'warn':'bad'}>{t.ready?'READY':t.installed?'REPAIR':'MISSING'}</b></div>):<div className="mission-empty">Build a mission plan to inspect prerequisites.</div>}
        <div className="mission-boundary"><ShieldCheck size={17}/><div><strong>TRUSTED LOCAL WORKER</strong><span>Durable execution stays outside the browser. Registered profiles, scope checks and operator approval are enforced by Phase 6.</span></div></div>
        <div className="mission-command"><span>LOCAL WORKER</span><code>python scripts/phase6_worker.py</code></div>
        <div className="mission-state"><CheckCircle2 size={15}/><span>{plan?.ready_to_execute?'ENVIRONMENT READY FOR APPROVAL':'PREPARATION REQUIRED'}</span></div>
      </aside></div>
    </section></div>}
  </>
}
