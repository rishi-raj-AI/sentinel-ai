export type TimelineItem={id:string;label:string;at?:string;state?:string}
export type PathItem={id:string;label:string;state:string}

export function TimelineView({items,index,onChange}:{items:TimelineItem[];index:number;onChange:(value:number)=>void}){
  const max=Math.max(0,items.length-1)
  const safe=Math.min(index,max)
  const current=items[safe]
  return <div className="timeline-view"><div className="timeline-current"><strong>{current?.label||'No events available'}</strong><span>{current?.at?new Date(current.at).toLocaleTimeString():'Waiting for data'}</span></div><input type="range" min={0} max={max} value={safe} onChange={e=>onChange(Number(e.target.value))} disabled={items.length<=1}/><small>{Math.min(safe+1,Math.max(1,items.length))} / {Math.max(1,items.length)}</small></div>
}

export function PathView({items}:{items:PathItem[]}){
  return <div className="path-view">{items.slice(0,8).map((item,i)=><div className={`path-view-item ${item.state}`} key={item.id}><i/><div><b>{item.id}</b><span>{item.label}</span></div>{i<Math.min(items.length,8)-1&&<em>→</em>}</div>)}</div>
}
