import { useEffect, useMemo, useState } from 'react'
import { Activity, BrainCircuit, Clock3, Database, FileText, GitBranch, History, Network, Search, ShieldCheck, X } from 'lucide-react'
import { PathView, TimelineView, type PathItem, type TimelineItem } from './timelineView'
import ReportStudio from './reportStudio'
import { activeMissionId, loadMissionWorkspace, rememberActiveMission, type MissionWorkspace } from './missionIntelligence'

type Tab='replay'|'evidence'|'twin'|'review'|'memory'|'report'

export default function IntelligenceWorkspace(){
  const [open,setOpen]=useState(false)
  const [missionId,setMissionId]=useState(activeMissionId())
  const [workspace,setWorkspace]=useState<MissionWorkspace>()
  const [tab,setTab]=useState<Tab>('replay')
  const [index,setIndex]=useState(0)
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')

  const load=async()=>{
    if(!missionId.trim()) return
    setBusy(true);setError('')
    try{
      const value=await loadMissionWorkspace(missionId)
      setWorkspace(value);rememberActiveMission(value);setIndex(0)
    }catch(e){setError(String(e))}finally{setBusy(false)}
  }

  useEffect(()=>{
    if(!open||!workspace?.mission_id) return
    const id=window.setInterval(async()=>{
      try{const value=await loadMissionWorkspace(workspace.mission_id);setWorkspace(value);rememberActiveMission(value)}catch{}
    },2500)
    return()=>window.clearInterval(id)
  },[open,workspace?.mission_id])

  const timeline:TimelineItem[]=useMemo(()=>workspace?.replay?.frames?.map(f=>({id:f.frame_id,label:f.label,at:f.at,state:f.state}))||[],[workspace])
  const path:PathItem[]=useMemo(()=>workspace?.twin?.nodes?.filter(n=>n.node_id!=='MISSION').map(n=>({id:n.node_id,label:n.label,state:n.state}))||[],[workspace])
  const supervisor=workspace?.snapshot?.supervisor
  const confidence=Math.round((supervisor?.confidence||0)*100)
  const coverage=Math.round((supervisor?.coverage||0)*100)
  const reportFindings=useMemo(()=>{
    const evidence=workspace?.evidence_workspace?.items||[]
    return evidence.slice(0,40).map(e=>({
      title:e.label,
      severity:e.counter_evidence?'medium':'info',
      summary:`${e.evidence_type} evidence${e.stage_id?` associated with ${e.stage_id}`:''}${e.attack_techniques?.length?`. ATT&CK: ${e.attack_techniques.join(', ')}`:''}.`,
      evidence:[e.evidence_id,e.source||'indexed mission evidence'].filter(Boolean) as string[],
      recommendation:e.counter_evidence?'Resolve this counter-evidence before increasing mission confidence.':'Preserve and correlate this evidence with the relevant mission stage.',
    }))
  },[workspace])
  const reportTimeline=useMemo(()=>timeline.map(t=>({label:t.label,at:t.at})),[timeline])

  return <>
    <button className="intel-workspace-launch" onClick={()=>setOpen(true)} title="Intelligence Workspace"><GitBranch size={14}/><span>V2 INTEL</span></button>
    {open&&<div className="intel-workspace-backdrop"><section className="intel-workspace-shell">
      <header><div><small>PHASES 8—11 / DERIVED INTELLIGENCE</small><h2>Mission Intelligence Workspace</h2></div><button onClick={()=>setOpen(false)}><X size={17}/></button></header>
      <div className="intel-connect"><Search size={15}/><input value={missionId} onChange={e=>setMissionId(e.target.value.toUpperCase())} placeholder="MISSION ID"/><button onClick={load} disabled={busy}>{busy?'LOADING…':'OPEN WORKSPACE'}</button></div>
      {error&&<div className="intel-error">{error}</div>}
      <div className="intel-kpis"><div><strong>{workspace?.snapshot?.mission?.status?.toUpperCase()||'—'}</strong><span>MISSION</span></div><div><strong>{workspace?.evidence_workspace?.count??0}</strong><span>EVIDENCE</span></div><div><strong>{confidence}%</strong><span>CONFIDENCE</span></div><div><strong>{coverage}%</strong><span>COVERAGE</span></div><div><strong>{workspace?.memory?.related?.length??0}</strong><span>RELATED</span></div></div>
      <nav className="intel-tabs">
        <button className={tab==='replay'?'active':''} onClick={()=>setTab('replay')}><Clock3 size={13}/>REPLAY</button>
        <button className={tab==='evidence'?'active':''} onClick={()=>setTab('evidence')}><Database size={13}/>EVIDENCE</button>
        <button className={tab==='twin'?'active':''} onClick={()=>setTab('twin')}><Network size={13}/>MISSION PATH</button>
        <button className={tab==='review'?'active':''} onClick={()=>setTab('review')}><BrainCircuit size={13}/>REVIEW</button>
        <button className={tab==='memory'?'active':''} onClick={()=>setTab('memory')}><History size={13}/>MEMORY</button>
        <button className={tab==='report'?'active':''} onClick={()=>setTab('report')}><FileText size={13}/>REPORT</button>
      </nav>
      <div className="intel-body">
        {tab==='replay'&&<div className="intel-panel"><div className="intel-panel-head"><strong>Mission Replay Studio</strong><span>{timeline.length} frames</span></div><TimelineView items={timeline} index={index} onChange={setIndex}/><div className="intel-replay-strip">{timeline.slice(Math.max(0,index-2),index+3).map((item,i)=><div key={item.id} className={timeline[Math.max(0,index-2)+i]?.id===timeline[index]?.id?'current':''}><i/><span>{item.label}</span><small>{item.state||'observed'}</small></div>)}</div></div>}
        {tab==='evidence'&&<div className="intel-panel"><div className="intel-panel-head"><strong>Evidence Explorer</strong><span>{workspace?.evidence_workspace?.facets?.counter_evidence||0} counter-evidence</span></div><div className="intel-evidence-grid">{workspace?.evidence_workspace?.items?.length?workspace.evidence_workspace.items.map(e=><article key={e.evidence_id} className={e.counter_evidence?'counter':''}><div><b>{e.evidence_type.toUpperCase()}</b><span>{e.stage_id||'UNASSIGNED'}</span></div><h4>{e.label}</h4><p>{e.attack_techniques?.join(' · ')||'No ATT&CK mapping recorded'}</p><footer><span>{e.confidence!=null?`${Math.round(e.confidence*100)}% confidence`:'confidence n/a'}</span>{e.counter_evidence&&<strong>COUNTER</strong>}</footer></article>):<div className="intel-empty">No indexed evidence for this mission yet.</div>}</div></div>}
        {tab==='twin'&&<div className="intel-panel"><div className="intel-panel-head"><strong>Digital Twin Mission Projection</strong><span>{workspace?.twin?.edges?.length||0} relationships</span></div><PathView items={path}/><div className="intel-node-grid">{workspace?.twin?.nodes?.map(n=><div key={n.node_id} className={`intel-node ${n.state}`}><i/><div><b>{n.node_id}</b><span>{n.label}</span></div><small>{n.evidence_count||0} evidence</small></div>)}</div></div>}
        {tab==='review'&&<div className="intel-panel"><div className="intel-panel-head"><strong>Multi-Agent Review</strong><span>{Math.round((workspace?.review?.quality_score||0)*100)}% quality</span></div><div className="intel-review-banner"><ShieldCheck size={18}/><div><b>{workspace?.review?.recommended_action||'awaiting-state'}</b><span>{supervisor?.verdict||'No supervisor verdict yet'}</span></div></div><div className="intel-review-grid">{workspace?.review?.stage_reviews?.map(r=><article key={r.stage_id}><header><b>{r.stage_id}</b><span>{r.agent}</span></header><strong>{r.assessment.toUpperCase()}</strong><div><span>SUPPORT {r.supporting_evidence}</span><span>COUNTER {r.counter_evidence}</span></div><small>{r.state}</small></article>)}</div></div>}
        {tab==='memory'&&<div className="intel-panel"><div className="intel-panel-head"><strong>Organizational Memory</strong><span>cross-mission similarity</span></div><div className="intel-memory-grid">{workspace?.memory?.related?.length?workspace.memory.related.map(m=><article key={m.mission_id}><div><b>{m.mission_id}</b><strong>{Math.round(m.similarity*100)}%</strong></div><p>{m.objective}</p><small>{m.reasons.join(' · ')}</small><footer>{m.status}</footer></article>):<div className="intel-empty">No related mission exceeds the similarity threshold yet.</div>}</div><div className="intel-lessons">{workspace?.memory?.lessons?.slice(0,5).map((l,i)=><div key={`${l.created_at}-${i}`}><Activity size={12}/><span>{l.lesson}</span></div>)}</div></div>}
        {tab==='report'&&<div className="intel-panel report-panel"><ReportStudio title={`Mission ${workspace?.mission_id||'Report'}`} objective={workspace?.snapshot?.mission?.objective||'No mission objective loaded'} status={workspace?.snapshot?.mission?.status||'draft'} confidence={supervisor?.confidence||0} findings={reportFindings} timeline={reportTimeline}/></div>}
      </div>
    </section></div>}
  </>
}
