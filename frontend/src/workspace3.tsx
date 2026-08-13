import { useEffect, useMemo, useState } from 'react'
import { BrainCircuit, ChevronRight, Command, Crosshair, Eye, Layers3, Maximize2, Play, Search, SlidersHorizontal, Sparkles, X } from 'lucide-react'

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
  const [replay,setReplay]=useState(72)
  const filtered=useMemo(()=>commands.filter(([label])=>label.toLowerCase().includes(query.toLowerCase())),[query])

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

  return <>
    <div className="workspace-dock" aria-label="Workspace dock">
      <button title="Sentinel Core" className={dock==='core'?'active':''} onClick={()=>setDock(dock==='core'?'none':'core')}><BrainCircuit size={16}/></button>
      <button title="Context Inspector" className={dock==='context'?'active':''} onClick={()=>setDock(dock==='context'?'none':'context')}><Crosshair size={16}/></button>
      <button title="Case Replay" className={dock==='replay'?'active':''} onClick={()=>setDock(dock==='replay'?'none':'replay')}><Play size={15}/></button>
      <button title="Command Palette" onClick={()=>setPalette(true)}><Command size={16}/></button>
      <button title="Focus Mode" className={focus?'active':''} onClick={()=>setFocus(v=>!v)}><Maximize2 size={16}/></button>
    </div>

    {dock!=='none'&&<aside className="workspace-inspector">
      <div className="inspector-head"><div><span>WORKSPACE / UI 3.0</span><strong>{dock==='core'?'Sentinel Core':dock==='context'?'Context Inspector':'Case Replay'}</strong></div><button onClick={()=>setDock('none')}><X size={14}/></button></div>
      {dock==='core'&&<div className="core-inspector"><div className="mini-orbit"><BrainCircuit size={30}/><i/><b/></div><div className="core-bars">{[['Reasoning',88],['Memory',74],['Knowledge',93],['Agent Fabric',81],['Twin Model',66]].map(([n,v])=><div key={String(n)}><span>{n}<b>{v}%</b></span><i><em style={{width:`${v}%`}}/></i></div>)}</div><div className="inspector-note"><Sparkles size={13}/>Operational visualization; workload indicators are UI state, not evidence.</div></div>}
      {dock==='context'&&<div className="context-stack"><div><Eye/><span><b>Focused Surface</b><small>Current laboratory workspace</small></span><ChevronRight/></div><div><Layers3/><span><b>Evidence Context</b><small>Linked case and graph state</small></span><ChevronRight/></div><div><SlidersHorizontal/><span><b>View Controls</b><small>Layout, density and overlays</small></span><ChevronRight/></div></div>}
      {dock==='replay'&&<div className="replay-panel"><div className="replay-clock">14:{String(Math.round(replay/2)).padStart(2,'0')}<small>SIMULATION REPLAY</small></div><input type="range" min="0" max="100" value={replay} onChange={e=>setReplay(Number(e.target.value))}/><div className="replay-ticks"><span>13:01</span><span>13:30</span><span>14:00</span><span>14:30</span></div><div className="replay-events"><i className="done"/><i className="done"/><i className="hot"/><i/><i/></div><p>Scrubber demonstrates time-oriented investigation replay. It does not modify case evidence.</p></div>}
    </aside>}

    {palette&&<div className="palette-backdrop" onMouseDown={()=>setPalette(false)}><div className="command-palette" onMouseDown={e=>e.stopPropagation()}>
      <div className="palette-search"><Search size={17}/><input autoFocus placeholder="Search Sentinel workspaces…" value={query} onChange={e=>setQuery(e.target.value)}/><kbd>ESC</kbd></div>
      <div className="palette-label">NAVIGATE</div>
      <div className="palette-results">{filtered.map(([label,key],i)=><button key={key} onClick={()=>{navigate(key);setPalette(false);setQuery('')}}><span><Command size={14}/>{label}</span><kbd>⌥{i+1}</kbd></button>)}</div>
      <div className="palette-footer"><span>⌘K command palette</span><span>/ global search</span><span>⌥1—9 navigate</span></div>
    </div></div>}
  </>
}
