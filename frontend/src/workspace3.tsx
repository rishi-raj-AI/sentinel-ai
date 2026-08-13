import { useEffect, useMemo, useState } from 'react'
import { BrainCircuit, ChevronRight, Command, Crosshair, Eye, Layers3, Maximize2, Play, Search, SlidersHorizontal, Sparkles, X } from 'lucide-react'
import { ACTIVE_MISSION_KEY, MISSION_EVENT, activeMissionId, loadMissionWorkspace, type MissionWorkspace } from './missionIntelligence'

const commands = [
  ['Command Center','command center'],['Investigations','investigations'],['SOC Operations','soc operations'],
  ['Threat Intelligence','threat intelligence'],['Knowledge Graph','knowledge graph'],['AppSec Lab','appsec lab'],
  ['Malware Lab','malware lab'],['Digital Twin','digital twin'],['Research Lab','research lab'],['Control Plane','control plane'],
] as const

function navigate(label:string){
  const buttons=[...document.querySelectorAll('nav button')]
  const target=buttons.find((b)=>b.textContent?.toLowerCase().includes(label.toLowerCase())) as HTMLButtonElement|undefined
  target?.click()
}

export default function WorkspaceLayer(){
  const [palette,setPalette]=useState(false)
  const [query,setQuery]=useState('')
  const [dock,setDock]=useState<'none'|'core'|'context'|'replay'>('none')
  const [focus,setFocus]=useState(false)
  const [replay,setReplay]=useState(0)
  const [mission,setMission]=useState<MissionWorkspace>()
  const filtered=useMemo(()=>commands.filter(([label])=>label.toLowerCase().includes(query.toLowerCase())),[query])

  useEffect(()=>{
    const sync=async()=>{const id=activeMissionId();if(!id){setMission(undefined);return}try{setMission(await loadMissionWorkspace(id))}catch{}}
    sync()
    const onMission=(e:Event)=>setMission((e as CustomEvent<MissionWorkspace>).detail)
    const onStorage=(e:StorageEvent)=>{if(e.key===ACTIVE_MISSION_KEY)sync()}
    window.addEventListener(MISSION_EVENT,onMission);window.addEventListener('storage',onStorage)
    const timer=window.setInterval(()=>{if(dock!=='none')sync()},3500)
    return()=>{window.removeEventListener(MISSION_EVENT,onMission);window.removeEventListener('storage',onStorage);window.clearInterval(timer)}
  },[dock])

  useEffect(()=>{
    const onKey=(e:KeyboardEvent)=>{
      if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();setPalette(v=>!v)}
      if(e.key==='Escape'){setPalette(false);setDock('none')}
      if(e.key==='/'&&!palette){e.preventDefault();const input=document.querySelector('.top-search input') as HTMLInputElement|null;input?.focus()}
      if(e.altKey&&/^[1-9]$/.test(e.key)){const i=Number(e.key)-1;if(commands[i])navigate(commands[i][1])}
    }
    window.addEventListener('keydown',onKey);return()=>window.removeEventListener('keydown',onKey)
  },[palette])

  useEffect(()=>{document.body.classList.toggle('focus-mode',focus);return()=>document.body.classList.remove('focus-mode')},[focus])

  const sup=mission?.snapshot?.supervisor
  const review=mission?.review
  const evidence=mission?.evidence_workspace?.count||0
  const frames=mission?.replay?.frames||[]
  const bars:[string,number][]=[
    ['Confidence',Math.round((sup?.confidence||0)*100)],['Coverage',Math.round((sup?.coverage||0)*100)],
    ['Review Quality',Math.round((review?.quality_score||0)*100)],['Evidence',Math.min(100,evidence*10)],
  ]
  const replayMax=Math.max(0,frames.length-1);const replaySafe=Math.min(replay,replayMax);const currentFrame=frames[replaySafe]

  return <>
    <div className="workspace-dock" aria-label="Workspace dock">
      <button title="Sentinel Core" className={dock==='core'?'active':''} onClick={()=>setDock(dock==='core'?'none':'core')}><BrainCircuit size={16}/></button>
      <button title="Context Inspector" className={dock==='context'?'active':''} onClick={()=>setDock(dock==='context'?'none':'context')}><Crosshair size={16}/></button>
      <button title="Case Replay" className={dock==='replay'?'active':''} onClick={()=>setDock(dock==='replay'?'none':'replay')}><Play size={15}/></button>
      <button title="Command Palette" onClick={()=>setPalette(true)}><Command size={16}/></button>
      <button title="Focus Mode" className={focus?'active':''} onClick={()=>setFocus(v=>!v)}><Maximize2 size={16}/></button>
    </div>

    {dock!=='none'&&<aside className="workspace-inspector">
      <div className="inspector-head"><div><span>WORKSPACE / LIVE STATE</span><strong>{dock==='core'?'Sentinel Core':dock==='context'?'Context Inspector':'Case Replay'}</strong></div><button onClick={()=>setDock('none')}><X size={14}/></button></div>
      {dock==='core'&&<div className="core-inspector"><div className="mini-orbit"><BrainCircuit size={30}/><i/><b/></div>{mission?<><div className="core-bars">{bars.map(([n,v])=><div key={n}><span>{n}<b>{v}{n==='Evidence'?'':'%'}</b></span><i><em style={{width:`${v}%`}}/></i></div>)}</div><div className="inspector-note"><Sparkles size={13}/>{mission.mission_id} · {mission.snapshot?.mission?.status||'unknown'} · {sup?.verdict||'no verdict'}</div></>:<div className="inspector-note"><Sparkles size={13}/>No active mission. Open V2 INTEL and load a mission to populate live indicators.</div>}</div>}
      {dock==='context'&&<div className="context-stack">{mission?<><div><Eye/><span><b>{mission.snapshot?.mission?.objective||'Active mission'}</b><small>{mission.mission_id} · {mission.snapshot?.mission?.status||'unknown'}</small></span><ChevronRight/></div><div><Layers3/><span><b>Evidence Context</b><small>{evidence} indexed · {sup?.contradictions||0} counter-evidence</small></span><ChevronRight/></div><div><SlidersHorizontal/><span><b>Supervisor</b><small>{Math.round((sup?.confidence||0)*100)}% confidence · {Math.round((sup?.coverage||0)*100)}% coverage</small></span><ChevronRight/></div></>:<div><Eye/><span><b>No active mission</b><small>Load one from V2 Intelligence.</small></span></div>}</div>}
      {dock==='replay'&&<div className="replay-panel">{frames.length?<><div className="replay-clock">{replaySafe+1}/{frames.length}<small>MISSION REPLAY · {mission?.mission_id}</small></div><input type="range" min="0" max={replayMax} value={replaySafe} onChange={e=>setReplay(Number(e.target.value))}/><div className="replay-ticks"><span>START</span><span>{currentFrame?.state||'observed'}</span><span>END</span></div><div className="replay-events">{frames.slice(0,5).map((f,i)=><i key={f.frame_id} className={i<=replaySafe?'done':''}/>)}</div><p><b>{currentFrame?.label||'Mission event'}</b><br/>{currentFrame?.at?new Date(currentFrame.at).toLocaleString():'No timestamp'}</p></>:<p>No live replay frames. Load a mission from V2 Intelligence first.</p>}</div>}
    </aside>}

    {palette&&<div className="palette-backdrop" onMouseDown={()=>setPalette(false)}><div className="command-palette" onMouseDown={e=>e.stopPropagation()}>
      <div className="palette-search"><Search size={17}/><input autoFocus placeholder="Search Sentinel workspaces…" value={query} onChange={e=>setQuery(e.target.value)}/><kbd>ESC</kbd></div>
      <div className="palette-label">NAVIGATE</div>
      <div className="palette-results">{filtered.map(([label,key],i)=><button key={key} onClick={()=>{navigate(key);setPalette(false);setQuery('')}}><span><Command size={14}/>{label}</span><kbd>⌥{i+1}</kbd></button>)}</div>
      <div className="palette-footer"><span>⌘K command palette</span><span>/ focus search</span><span>⌥1—9 navigate</span></div>
    </div></div>}
  </>
}
