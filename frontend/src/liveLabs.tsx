import { useEffect, useState } from 'react'
import { Activity, Database, FlaskConical, GitBranch, Globe2, Network, RefreshCw, ShieldCheck } from 'lucide-react'

const API=(import.meta.env.VITE_API_URL||'http://127.0.0.1:8765').replace(/\/$/,'')

type Lab='twin'|'intel'|'graph'|'research'|'control'
type Props={lab:Lab;caseId?:string}

async function get(path:string){
  const r=await fetch(`${API}${path}`,{headers:{Accept:'application/json','X-Sentinel-Role':'viewer'}})
  const body=await r.json().catch(()=>({}))
  if(!r.ok) throw new Error(body?.detail||`${r.status} ${r.statusText}`)
  return body
}

export default function LiveLab({lab,caseId}:Props){
  const [data,setData]=useState<any>()
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const cfg={
    twin:['Digital Twin','Live modeled-control coverage and active mission infrastructure context.',Network],
    intel:['Threat Intelligence','Persisted shared intelligence generated from Sentinel evidence sources.',Globe2],
    graph:['Knowledge Graph','Real case evidence relationships, not a demonstration topology.',GitBranch],
    research:['Research & Evaluation','Persisted benchmark scenarios, summary and leaderboard.',FlaskConical],
    control:['Control Plane','Live governance statistics and audited policy state.',ShieldCheck],
  } as const
  const [title,subtitle,Icon]=cfg[lab]

  const load=async()=>{
    setBusy(true);setError('')
    try{
      let out:any
      if(lab==='twin') out=await get('/api/x/twin/coverage')
      else if(lab==='intel') out=await get('/api/x/insights?limit=100')
      else if(lab==='graph'){
        if(!caseId) out={message:'Open a forensic case first from Investigations or Sentinel AI.'}
        else out=await get(`/api/cases/${encodeURIComponent(caseId)}/graph?max_nodes=250&max_edges=500`)
      }else if(lab==='research'){
        const [summary,scenarios,leaderboard]=await Promise.all([get('/api/x/evaluation/summary'),get('/api/x/evaluation/scenarios'),get('/api/x/evaluation/leaderboard')])
        out={summary,scenarios,leaderboard}
      }else out=await get('/api/x/control/stats')
      setData(out)
    }catch(e){setError(String(e))}finally{setBusy(false)}
  }

  useEffect(()=>{load()},[lab,caseId])

  return <div className="live-lab">
    <div className="live-lab-hero"><div className="live-lab-icon"><Icon size={26}/></div><div><span>LIVE DATA SURFACE</span><h1>{title}</h1><p>{subtitle}</p></div><button onClick={load} disabled={busy}><RefreshCw size={14} className={busy?'spin':''}/>{busy?'LOADING':'REFRESH'}</button></div>
    <section className="live-lab-card"><header><div><Activity size={14}/><strong>BACKEND RESPONSE</strong></div><span>{error?'ERROR':data?'LIVE':'WAITING'}</span></header>{error?<div className="live-lab-error">{error}</div>:data?<pre>{JSON.stringify(data,null,2)}</pre>:<div className="live-lab-empty"><Database size={22}/>Loading persisted Sentinel state…</div>}</section>
  </div>
}
