import { useEffect, useMemo, useState } from 'react'
import { Bot, BrainCircuit, ChevronRight, CircleAlert, Play, RefreshCw, Send, ShieldCheck, TerminalSquare, X } from 'lucide-react'
import { askCaseCopilot, listInvestigations, loadCommandData, loadCopilotStatus, runInvestigation, type CaseSummary, type CopilotStatus, type InvestigationRun } from './api'

type Message={role:'user'|'assistant';text:string;meta?:string}

export default function PersonalAI(){
  const [open,setOpen]=useState(false)
  const [cases,setCases]=useState<CaseSummary[]>([])
  const [caseId,setCaseId]=useState('')
  const [status,setStatus]=useState<CopilotStatus>({})
  const [messages,setMessages]=useState<Message[]>([{role:'assistant',text:'Select a case and ask me about its evidence, findings, timeline, detections, or next investigative step.'}])
  const [question,setQuestion]=useState('What should I investigate next in this case?')
  const [objective,setObjective]=useState('Investigate the available evidence and identify the strongest supported hypothesis')
  const [runs,setRuns]=useState<InvestigationRun[]>([])
  const [current,setCurrent]=useState<InvestigationRun>()
  const [busy,setBusy]=useState('')
  const [error,setError]=useState('')
  const selected=useMemo(()=>cases.find(c=>c.case_id===caseId),[cases,caseId])

  const refresh=async()=>{
    setError('')
    try{
      const [data,cp]=await Promise.all([loadCommandData(),loadCopilotStatus()])
      setCases(data.cases);setStatus(cp)
      const next=caseId&&data.cases.some(c=>c.case_id===caseId)?caseId:(data.cases[0]?.case_id||'')
      setCaseId(next)
      if(next) setRuns(await listInvestigations(next))
    }catch(e){setError(String(e))}
  }
  useEffect(()=>{if(open) refresh()},[open])
  useEffect(()=>{if(!open||!caseId)return;listInvestigations(caseId).then(setRuns).catch(()=>setRuns([]))},[caseId,open])

  const ask=async()=>{
    const q=question.trim();if(!q||!caseId)return
    setBusy('ask');setError('');setMessages(m=>[...m,{role:'user',text:q}]);setQuestion('')
    try{
      const r=await askCaseCopilot(caseId,q)
      setMessages(m=>[...m,{role:'assistant',text:r.answer||'No answer returned.',meta:`${r.mode||'grounded'} · ${r.source_count||0} sources`}])
    }catch(e){setError(String(e))}finally{setBusy('')}
  }
  const investigate=async()=>{
    if(!caseId||!objective.trim())return
    setBusy('run');setError('')
    try{const r=await runInvestigation(caseId,objective.trim(),25);setCurrent(r);setRuns(await listInvestigations(caseId))}catch(e){setError(String(e))}finally{setBusy('')}
  }
  const jump=()=>{window.dispatchEvent(new CustomEvent('sentinel:navigate',{detail:{view:'cases',caseId}}));setOpen(false)}

  return <>
    <button className="personal-ai-launch" onClick={()=>setOpen(true)}><Bot size={15}/><span>ASK SENTINEL</span></button>
    {open&&<div className="personal-ai-backdrop"><section className="personal-ai-shell">
      <header><div><small>PERSONAL AI / EVIDENCE-GROUNDED COPILOT</small><h2>Sentinel AI</h2></div><button onClick={()=>setOpen(false)}><X size={17}/></button></header>
      <div className="personal-ai-casebar"><select value={caseId} onChange={e=>setCaseId(e.target.value)}><option value="">SELECT CASE</option>{cases.map(c=><option key={c.case_id} value={c.case_id}>{c.case_id} — {c.title||'Untitled'}</option>)}</select><span className={status.configured?'model':'fallback'}><BrainCircuit size={13}/>{status.configured?`MODEL · ${status.model||'configured'}`:'DETERMINISTIC MODE'}</span><button onClick={refresh}><RefreshCw size={13}/>REFRESH</button></div>
      {error&&<div className="personal-ai-error"><CircleAlert size={14}/>{error}</div>}
      {!cases.length?<div className="personal-ai-empty"><TerminalSquare size={28}/><h3>Create your first investigation case</h3><p>The backend case engine is ready, but the repository currently blocks browser-side case creation. Run this once from the project root, then click Refresh:</p><code>python -c "from app.forensics.case_manager import CaseManager; print(CaseManager('cases').create_case('My First Investigation','Created from Sentinel AI'))"</code></div>:
      <div className="personal-ai-grid">
        <div className="personal-ai-chat"><div className="personal-ai-title"><ShieldCheck size={14}/>ASK SENTINEL <span>{selected?.case_id}</span></div><div className="personal-ai-messages">{messages.map((m,i)=><div key={i} className={`personal-msg ${m.role}`}><b>{m.role==='user'?'YOU':'SENTINEL'}</b><p>{m.text}</p>{m.meta&&<small>{m.meta}</small>}</div>)}</div><div className="personal-ai-input"><textarea value={question} onChange={e=>setQuestion(e.target.value)} onKeyDown={e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();ask()}}}/><button disabled={busy==='ask'||!caseId} onClick={ask}><Send size={14}/>{busy==='ask'?'THINKING…':'ASK'}</button></div></div>
        <aside className="personal-ai-investigate"><div className="personal-ai-title"><Play size={14}/>AUTONOMOUS INVESTIGATION</div><textarea value={objective} onChange={e=>setObjective(e.target.value)}/><button className="personal-primary" disabled={busy==='run'||!caseId} onClick={investigate}><Play size={14}/>{busy==='run'?'ANALYZING…':'RUN INVESTIGATION'}</button>{current&&<div className="personal-run-result"><strong>{current.overall_confidence_percent??0}%</strong><span>{current.overall_confidence||'confidence'}</span><h4>{current.leading_hypothesis?.statement||'No leading hypothesis'}</h4>{current.recommended_actions?.slice(0,4).map((a,i)=><p key={i}>→ {a}</p>)}</div>}<div className="personal-runs"><b>RECENT RUNS</b>{runs.slice(0,5).map((r,i)=><button key={r.run_id||i} onClick={()=>setCurrent(r)}><span>{r.objective||'Investigation'}</span><small>{r.overall_confidence_percent??0}%</small></button>)}</div><button className="personal-jump" onClick={jump}><span>OPEN CASE WORKSPACE</span><ChevronRight size={14}/></button></aside>
      </div>}
    </section></div>}
  </>
}
