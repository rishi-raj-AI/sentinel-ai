import { BrainCircuit, Cpu, Globe2, Orbit, Radar } from 'lucide-react'

export function ReactorXL({ online = true }: { online?: boolean }) {
  return <div className={`reactor-xl ${online ? 'online' : 'offline'}`}>
    <div className="rx halo"/><div className="rx ring-a"/><div className="rx ring-b"/><div className="rx ring-c"/>
    <div className="rx-core"><BrainCircuit size={32}/><span>SX</span></div>
    <i className="rx-particle p1"/><i className="rx-particle p2"/><i className="rx-particle p3"/>
  </div>
}

export function AgentWall({ rows }: { rows: Array<[string,string,number,string]> }) {
  return <div className="agent-wall">{rows.map(([name,task,pct,tone]) => <div className="agent-tile" key={name}>
    <div className={`agent-led ${tone}`}/><div className="agent-icon"><Cpu size={15}/></div>
    <div className="agent-info"><strong>{name}</strong><span>{task}</span><div className="agent-meter"><i style={{width:`${pct}%`}}/></div></div>
    <div className="agent-pct">{pct}<small>%</small></div>
  </div>)}</div>
}

export function GlobeField({ primary = 4, secondary = 12 }: { primary?: number; secondary?: number }) {
  return <div className="threat-globe">
    <div className="globe-shell"><div className="globe-longitudes"/><div className="globe-latitudes"/><div className="globe-sweep"/><i className="threat-dot td1"/><i className="threat-dot td2"/><i className="threat-dot td3"/><i className="threat-dot td4"/><Globe2 size={58}/></div>
    <div className="globe-copy"><strong>GLOBAL SIGNAL FIELD</strong><span>LAB VISUALIZATION</span><div><b>{String(primary).padStart(2,'0')}</b> active regions</div><div><b>{String(secondary).padStart(2,'0')}</b> correlated signals</div></div>
  </div>
}

export function RadarField() {
  return <div className="world-radar"><div className="radar-rings"><div className="radar-beam"/><i className="rb1"/><i className="rb2"/><i className="rb3"/><i className="rb4"/></div><div className="radar-side"><b><Radar size={11}/> LIVE RADAR</b><span>assets</span><span>signals</span><span>agents</span><span>controls</span></div></div>
}

export function FabricMap({ labels }: { labels: string[] }) {
  const nodes = [
    {x:9,y:46,tone:'violet'},{x:28,y:25,tone:'cyan'},{x:49,y:47,tone:'cyan'},{x:72,y:24,tone:'red'},
    {x:82,y:67,tone:'violet'},{x:47,y:82,tone:'green'},{x:18,y:80,tone:'cyan'},{x:94,y:40,tone:'amber'},
  ]
  const edges = [[0,1],[1,2],[2,3],[2,4],[5,2],[6,1],[4,3],[3,7],[4,7]]
  return <div className="cyber-fabric"><div className="fabric-grid"/><div className="fabric-scan"/>
    <svg viewBox="0 0 100 100" preserveAspectRatio="none">{edges.map(([a,b],i)=><g key={i}><line x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y} className="fabric-edge"/><circle r=".65" className="packet"><animateMotion dur={`${2.6+i*.35}s`} repeatCount="indefinite" path={`M ${nodes[a].x} ${nodes[a].y} L ${nodes[b].x} ${nodes[b].y}`}/></circle></g>)}</svg>
    {nodes.map((n,i)=><div key={i} className={`fabric-node tone-${n.tone}`} style={{left:`${n.x}%`,top:`${n.y}%`}}><span/><b>{labels[i] || `NODE ${i+1}`}</b>{i===2&&<i/>}</div>)}
    <div className="sim-label"><Orbit size={12}/> SIMULATION LAYER</div>
  </div>
}
