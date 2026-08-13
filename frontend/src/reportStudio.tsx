import { useMemo, useState } from 'react'
import { FileText, Layers3, ShieldCheck } from 'lucide-react'

type Finding={title:string;severity?:string;summary?:string;evidence?:string[];recommendation?:string}
export type ReportStudioProps={title?:string;objective?:string;status?:string;confidence?:number;findings?:Finding[];timeline?:Array<{label:string;at?:string}>}

export default function ReportStudio({title='Sentinel Report',objective='No objective selected',status='draft',confidence=0,findings=[],timeline=[]}:ReportStudioProps){
  const [mode,setMode]=useState<'executive'|'technical'>('executive')
  const counts=useMemo(()=>findings.reduce((acc,f)=>{const k=(f.severity||'info').toLowerCase();acc[k]=(acc[k]||0)+1;return acc},{} as Record<string,number>),[findings])
  return <section className="report-studio">
    <header><div><span>REPORT STUDIO</span><h3>{title}</h3><p>{objective}</p></div><div className="report-mode"><button className={mode==='executive'?'active':''} onClick={()=>setMode('executive')}>EXECUTIVE</button><button className={mode==='technical'?'active':''} onClick={()=>setMode('technical')}>TECHNICAL</button></div></header>
    <div className="report-kpis"><div><ShieldCheck size={14}/><strong>{status.toUpperCase()}</strong><span>STATUS</span></div><div><Layers3 size={14}/><strong>{findings.length}</strong><span>FINDINGS</span></div><div><FileText size={14}/><strong>{Math.round(confidence*100)}%</strong><span>CONFIDENCE</span></div></div>
    {mode==='executive'?<div className="report-executive"><article><h4>Executive Summary</h4><p>{findings.length?`${findings.length} findings are recorded for this assessment. The current confidence score is ${Math.round(confidence*100)}%. Review critical and high-severity items first, then validate remediation against the supporting evidence.`:'No findings have been recorded yet. The report will populate as evidence and validated conclusions become available.'}</p></article><article><h4>Risk Distribution</h4><div className="report-risk">{['critical','high','medium','low','info'].map(k=><div key={k}><span>{k}</span><b>{counts[k]||0}</b></div>)}</div></article></div>:<div className="report-technical"><div className="report-findings">{findings.length?findings.map((f,i)=><article key={`${f.title}-${i}`}><header><b>{f.title}</b><span>{(f.severity||'info').toUpperCase()}</span></header><p>{f.summary||'No technical summary provided.'}</p>{f.evidence?.length?<ul>{f.evidence.map((e,j)=><li key={j}>{e}</li>)}</ul>:null}{f.recommendation?<small>{f.recommendation}</small>:null}</article>):<div className="report-empty">No validated technical findings yet.</div>}</div><aside><h4>Timeline</h4>{timeline.slice(-8).map((t,i)=><div className="report-time" key={`${t.label}-${i}`}><i/><span>{t.label}</span><small>{t.at?new Date(t.at).toLocaleString():'—'}</small></div>)}</aside></div>}
  </section>
}
