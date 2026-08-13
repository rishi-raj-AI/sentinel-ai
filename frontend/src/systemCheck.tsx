import { useEffect, useState } from 'react'
import { Activity, CheckCircle2, CircleAlert, RefreshCw, X } from 'lucide-react'

const API=(import.meta.env.VITE_API_URL||'http://127.0.0.1:8765').replace(/\/$/,'')
const OPS=(import.meta.env.VITE_OPERATIONS_URL||'http://127.0.0.1:8766').replace(/\/$/,'')

type Check={name:string;url:string;ok:boolean;status?:number;detail?:string}
const specs=[
  ['CORE API',`${API}/healthz`],['READINESS',`${API}/readyz`],['CASES',`${API}/api/cases`],
  ['PLATFORM STATUS',`${API}/api/x/status`],['TOOL MANAGER',`${API}/api/x/tools`],
  ['DIGITAL TWIN',`${API}/api/x/twin/coverage`],['CONTROL PLANE',`${API}/api/x/control/stats`],
  ['EVALUATION',`${API}/api/x/evaluation/summary`],['TELEMETRY',`${OPS}/healthz`],
] as const

export default function SystemCheck(){
  const [open,setOpen]=useState(false);const [checks,setChecks]=useState<Check[]>([]);const [busy,setBusy]=useState(false)
  const run=async()=>{setBusy(true);const rows:Check[]=[];for(const [name,url] of specs){try{const r=await fetch(url,{headers:{Accept:'application/json','X-Sentinel-Role':'viewer'}});rows.push({name,url,ok:r.ok,status:r.status,detail:r.ok?'reachable':r.statusText})}catch(e){rows.push({name,url,ok:false,detail:String(e)})}}setChecks(rows);setBusy(false)}
  useEffect(()=>{if(open)run()},[open])
  const healthy=checks.length&&checks.every(c=>c.ok)
  return <>{<button className="system-check-launch" onClick={()=>setOpen(true)}><Activity size={14}/><span>SYSTEM CHECK</span></button>}{open&&<div className="system-check-backdrop"><section className="system-check-shell"><header><div><small>LIVE FUNCTION VERIFICATION</small><h2>Sentinel Readiness</h2></div><button onClick={()=>setOpen(false)}><X size={17}/></button></header><div className={`system-check-summary ${healthy?'ok':'warn'}`}>{healthy?<CheckCircle2 size={18}/>:<CircleAlert size={18}/>}<div><strong>{busy?'CHECKING…':healthy?'ALL CORE SERVICES REACHABLE':'ATTENTION REQUIRED'}</strong><span>{checks.filter(c=>c.ok).length}/{specs.length} checks passing</span></div><button onClick={run} disabled={busy}><RefreshCw size={13}/>RUN AGAIN</button></div><div className="system-check-list">{checks.map(c=><div key={c.name} className={c.ok?'ok':'bad'}><i/><div><strong>{c.name}</strong><span>{c.detail}</span></div><b>{c.status||'ERR'}</b></div>)}</div><footer>This verifies reachability and readiness. Workflow actions are validated separately by using them from Sentinel AI, Tool Manager, Mission Control and V2 Intelligence.</footer></section></div>}</>
}
