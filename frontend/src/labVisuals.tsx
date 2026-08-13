import { ChevronRight, CircleDot, Hexagon, Sparkles } from 'lucide-react'

export function ReasoningTimeline({ rows }: { rows: Array<[string,string,string]> }) {
  return <div className="reason-timeline">{rows.map(([t,msg,tone],i)=><div className="reason-event" key={`${t}-${msg}`}><time>{t}</time><div className={`reason-node ${tone}`}/><div><strong>{msg}</strong><span>{i===rows.length-1?'Awaiting operator review':'Evidence-linked reasoning event'}</span></div></div>)}</div>
}

export function IntelligenceTicker({ items }: { items: string[] }) {
  return <div className="intel-ticker"><div className="ticker-label"><CircleDot size={10}/> LIVE STREAM</div><div className="ticker-window"><div className="ticker-track">{[...items,...items].map((x,i)=><span key={i}><CircleDot size={8}/>{x}</span>)}</div></div></div>
}

export function ByteMatrix() {
  const rows = [
    ['00000000','4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00','MZ..............'],
    ['00000010','B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00','........@.......'],
    ['00000020','50 45 00 00 64 86 06 00 D1 7A 2F 65 00 00 00 00','PE..d....z/e....'],
    ['00000030','0B 01 02 00 00 10 00 00 00 20 00 00 00 00 00 00','......... ......'],
  ]
  return <div className="hex-lab"><div className="hex-head"><span>OFFSET</span><span>HEX BYTES</span><span>ASCII</span></div>{rows.map(r=><div className="hex-row" key={r[0]}><b>{r[0]}</b><code>{r[1]}</code><em>{r[2]}</em></div>)}</div>
}

export function AnalysisWorkspace() {
  const funcs=['entry_point','initialize_runtime','context_check','dispatch_worker','process_result','cleanup']
  return <div className="reverse-grid"><div className="function-list"><div className="mini-title">FUNCTION INDEX</div>{funcs.map((f,i)=><button key={f} className={i===2?'selected':''}><Hexagon size={11}/>{f}<span>0x{(4096+i*144).toString(16)}</span></button>)}</div><div className="decompiler"><div className="mini-title">STRUCTURE VIEW / LAB</div><pre><span>block_01</span>{`\n`}  ├─ initialize context{`\n`}  ├─ validate state{`\n`}  ├─ process input{`\n`}  └─ return result</pre></div><div className="cfg-view"><div className="mini-title">CONTROL FLOW</div><div className="cfg-node">ENTRY</div><ChevronRight/><div className="cfg-node violet">CHECK</div><ChevronRight/><div className="cfg-node green">RESULT</div></div></div>
}

export function CoreDialogue() {
  return <div className="core-dialogue"><div className="dialogue-orb"><Sparkles size={17}/></div><div><div className="mini-title">SENTINEL CORE</div><p>Three competing interpretations remain. The primary path has the strongest evidence support, while one collection gap still limits escalation.</p><div className="hypothesis-bars"><div><span>Primary hypothesis</span><b>87%</b><i style={{width:'87%'}}/></div><div><span>Alternative context</span><b>63%</b><i style={{width:'63%'}}/></div><div><span>Low-support path</span><b>18%</b><i style={{width:'18%'}}/></div></div></div></div>
}
