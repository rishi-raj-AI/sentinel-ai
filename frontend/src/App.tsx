import { useEffect, useMemo, useState } from 'react'
import {
  Activity, Aperture, Bell, Binary, BrainCircuit, Bug, ChevronRight, CircleDot,
  Command, Database, FlaskConical, GitBranch, Globe2, Hexagon, Layers3, LockKeyhole,
  Maximize2, Menu, Network, Orbit, Radar, RefreshCw, Search, ServerCog, ShieldCheck,
  X,
} from 'lucide-react'
import { loadCaseOverview, loadCommandData, type CaseSummary } from './api'
import { AgentWall, FabricMap, GlobeField, RadarField, ReactorXL } from './visuals'
import { AnalysisWorkspace, ByteMatrix, CoreDialogue, IntelligenceTicker, ReasoningTimeline } from './labVisuals'

type View = 'command'|'cases'|'soc'|'intel'|'graph'|'appsec'|'malware'|'twin'|'research'|'control'
type CommandData = Awaited<ReturnType<typeof loadCommandData>>

const nav: { id: View; label: string; icon: any }[] = [
  {id:'command',label:'Command Center',icon:Command},{id:'cases',label:'Investigations',icon:Layers3},
  {id:'soc',label:'SOC Operations',icon:Radar},{id:'intel',label:'Threat Intelligence',icon:Globe2},
  {id:'graph',label:'Knowledge Graph',icon:GitBranch},{id:'appsec',label:'AppSec Lab',icon:Bug},
  {id:'malware',label:'Malware Lab',icon:Binary},{id:'twin',label:'Digital Twin',icon:Orbit},
  {id:'research',label:'Research Lab',icon:FlaskConical},{id:'control',label:'Control Plane',icon:LockKeyhole},
]

const empty: CommandData = {status:{},cases:[],control:{},twin:{},evaluation:{},insights:{},health:{},ready:{}}
const fabricLabels=['IDENTITY','API GATEWAY','APP CLUSTER','PROD DB','CLOUD IAM','SOC SENSOR','EDGE','CONTROL']
const agents:[string,string,number,string][]=[
  ['NETWORK ANALYST','Correlating flow evidence',92,'cyan'],['COUNTER-EVIDENCE','Testing alternate hypotheses',84,'violet'],
  ['ARTIFACT ANALYST','Artifact queue synchronized',71,'amber'],['IDENTITY ANALYST','Privilege paths updated',88,'green'],
  ['SOC SUPERVISOR','Reconciling specialist findings',79,'cyan'],
]
const intelItems=['CVE intelligence synchronized','ATT&CK graph active','Identity graph updated','Shared insight threshold satisfied','Twin coverage recalculated','Evaluation benchmark recorded']
const reasoningRows:[string,string,string][]=[['16:02','Evidence graph refreshed','cyan'],['16:04','Alternative context detected','violet'],['16:05','Confidence recalculated','amber'],['16:07','Collection gap preserved','red'],['16:09','Supervisor synthesis ready','green']]

function Pill({children,tone='cyan'}:{children:any;tone?:'cyan'|'violet'|'amber'|'red'|'green'}){return <span className={`pill pill-${tone}`}><span className="pill-dot"/>{children}</span>}
function Panel({title,kicker,action,children,className=''}:{title:string;kicker?:string;action?:any;children:any;className?:string}){return <section className={`panel ${className}`}><div className="panel-glow"/><div className="panel-head"><div><div className="eyebrow">{kicker}</div><h3>{title}</h3></div>{action}</div>{children}</section>}
function Metric({label,value,sub,tone='cyan'}:{label:string;value:string|number;sub:string;tone?:string}){return <div className={`metric metric-${tone}`}><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-sub">{sub}</div></div>}

function CommandCenter({data,onSelectCase}:{data:CommandData;onSelectCase:(c:CaseSummary)=>void}){
  const healthy=data.health.status==='ok'&&data.ready.status==='ready'
  const storeCount=Object.values(data.status.stores||{}).filter(Boolean).length
  return <div className="page-transition">
    <IntelligenceTicker items={intelItems}/>
    <div className="hero-2">
      <div><div className="eyebrow">SENTINEL X / GLOBAL SECURITY FABRIC</div><h1>Cyber Command Center</h1><p>Evidence-grounded autonomous security operations across investigations, code, identity, cloud and simulated infrastructure.</p></div>
      <div className="core-stage"><ReactorXL online={healthy}/><div className="core-stage-copy"><strong>{healthy?'SENTINEL CORE ONLINE':'CORE DEGRADED'}</strong><span>{data.status.generation||'X12'} · API {data.status.backend_api_version||'1.0'}</span><i>AI FABRIC / NOMINAL</i></div></div>
    </div>
    <div className="metrics-grid"><Metric label="ACTIVE CASES" value={data.cases.length} sub="investigation workspaces"/><Metric label="DATA STORES" value={storeCount||7} sub="persistent intelligence layers" tone="violet"/><Metric label="CONTROL TENANTS" value={data.control.tenant_count??0} sub={`${data.control.audit_decisions??0} policy decisions`} tone="amber"/><Metric label="TWIN COVERAGE" value={`${Math.round((data.twin.coverage_ratio??0)*100)}%`} sub="modeled control coverage" tone="green"/></div>
    <div className="command-grid ui2-grid">
      <Panel title="Operational Digital Twin" kicker="X8 / PREDICTIVE DEFENSE" className="span-2 cinematic" action={<Pill tone="violet">LIVE MODEL</Pill>}><FabricMap labels={fabricLabels}/></Panel>
      <Panel title="Sentinel Core / Agent Wall" kicker="MULTI-AGENT ORCHESTRATION" className="agent-panel" action={<Activity size={16} className="cyan"/>}><AgentWall rows={agents}/></Panel>
      <Panel title="Global Signal Field" kicker="INTELLIGENCE RADAR" action={<Pill tone="cyan">LAB VIEW</Pill>}><GlobeField primary={4} secondary={(data.insights.insight_count??0)+11}/></Panel>
      <Panel title="Investigation Queue" kicker="EVIDENCE-FIRST CASES"><div className="case-list">{data.cases.slice(0,6).map((c,i)=><button className="case-row" key={c.case_id} onClick={()=>onSelectCase(c)}><span className={`severity ${i===0?'sev-high':'sev-med'}`}/><span className="case-main"><strong>{c.case_id}</strong><small>{c.title||'Security investigation'}</small></span><span className="case-meta">{c.evidence_count??0}<small>evidence</small></span><ChevronRight size={15}/></button>)}{!data.cases.length&&<div className="empty-state"><Aperture size={26}/><span>No active cases detected</span></div>}</div></Panel>
      <Panel title="Live Radar" kicker="OPERATIONS / TELEMETRY"><RadarField/></Panel>
      <Panel title="AI Reasoning Timeline" kicker="EXPLAINABLE DECISIONS"><ReasoningTimeline rows={reasoningRows}/></Panel>
      <Panel title="Sentinel Core Dialogue" kicker="HYPOTHESIS VIEW"><CoreDialogue/></Panel>
      <Panel title="Security Fabric" kicker="BACKEND / X1—X12" className="span-2"><div className="phase-grid">{Object.entries(data.status.phases||{}).map(([k,v])=><div className="phase-chip" key={k}><Hexagon size={13}/><strong>{k}</strong><span>{v}</span></div>)}</div></Panel>
    </div>
  </div>
}

function InvestigationLab({selected,overview}:{selected?:CaseSummary;overview:any}){
  return <div className="page-transition"><div className="module-hero hero-compact"><div className="module-icon"><Layers3 size={27}/></div><div><div className="eyebrow">EVIDENCE / TIMELINE / GRAPH / AI NOTEBOOK</div><h1>Investigation Lab</h1><p>Synchronized case workspace with evidence context and grounded reasoning.</p></div></div>
    <div className="workspace-grid investigation-grid"><Panel title={selected?.case_id||'No Case Selected'} kicker="CASE OVERVIEW" className="span-2"><div className="case-hero"><div><h2>{selected?.title||'Select an investigation from Command Center'}</h2><p>{overview?.brief?.executive_summary||'Evidence, detections, graph relationships and AI reasoning converge here.'}</p></div><Pill tone={selected?.status==='closed'?'green':'amber'}>{selected?.status||'READY'}</Pill></div><div className="evidence-grid"><Metric label="EVENTS" value={overview?.stats?.events??'—'} sub="timeline records"/><Metric label="EVIDENCE" value={overview?.stats?.evidence??selected?.evidence_count??'—'} sub="preserved items" tone="violet"/><Metric label="SIGMA" value={overview?.stats?.sigma_detections??'—'} sub="detections" tone="amber"/><Metric label="GRAPH" value={overview?.stats?.graph_nodes??'—'} sub="connected nodes" tone="green"/></div></Panel>
    <Panel title="Evidence Fabric" kicker="RELATIONSHIP MAP"><FabricMap labels={['EVIDENCE','FLOW','PROCESS','IDENTITY','RULE','TIMELINE','FILE','REPORT']}/></Panel><Panel title="Reasoning Timeline" kicker="AUDITABLE AI"><ReasoningTimeline rows={reasoningRows}/></Panel><Panel title="Sentinel Dialogue" kicker="GROUNDED COPILOT" className="span-2"><CoreDialogue/></Panel></div>
  </div>
}

function LabView({view,data}:{view:View;data:CommandData}){
  const cfg:Record<string,[string,string,any,string]>={soc:['Autonomous SOC','Multi-agent defensive analysis and evidence-grounded triage.',Radar,'X9 SECURITY FUSION'],intel:['Threat Intelligence','Cyber knowledge, generalized insights and source-aware intelligence.',Globe2,'X2 + X12 INTELLIGENCE'],graph:['Knowledge Graph','Traverse vulnerabilities, products, evidence, identities and relationships.',Network,'X2 KNOWLEDGE INTELLIGENCE'],appsec:['AppSec Laboratory','Static code, dependency, secret and supply-chain analysis.',Bug,'X7 SOFTWARE SECURITY'],malware:['Reverse Engineering Lab','Artifact structure, bytes, strings, indicators and behavioral references.',Binary,'X5 ARTIFACT INTELLIGENCE'],twin:['Digital Twin','Predictive infrastructure modeling, path simulation and control coverage.',Orbit,'X8 SIMULATION ENGINE'],research:['Research & Evaluation Lab','Benchmark Sentinel agents with reproducible scenarios and quality metrics.',FlaskConical,'X11 EVALUATION LAB'],control:['Enterprise Control Plane','Tenant policy, autonomy ceilings, approvals and auditable decisions.',ShieldCheck,'X10 GOVERNANCE']}
  const [title,subtitle,Icon,kicker]=cfg[view]||cfg.soc
  const special=view==='malware'?'artifact':view==='twin'?'twin':view==='research'?'research':view==='control'?'control':view==='intel'?'intel':view==='soc'?'soc':'generic'
  return <div className="page-transition module-page"><div className="module-hero"><div className="module-icon"><Icon size={30}/></div><div><div className="eyebrow">{kicker}</div><h1>{title}</h1><p>{subtitle}</p></div></div>
    {special==='artifact'&&<div className="module-grid lab-deep"><Panel title="Byte Matrix" kicker="STATIC ARTIFACT VIEW" className="span-2"><ByteMatrix/></Panel><Panel title="Structure Workspace" kicker="ANALYSIS SURFACE" className="span-2"><AnalysisWorkspace/></Panel><Panel title="Sentinel Interpretation" kicker="EVIDENCE-GROUNDED"><CoreDialogue/></Panel><Panel title="Artifact State" kicker="LAB TELEMETRY"><div className="status-stack"><div><Database/><span>Artifact store</span><Pill tone="green">READY</Pill></div><div><BrainCircuit/><span>Analysis layer</span><Pill tone="violet">ACTIVE</Pill></div><div><ShieldCheck/><span>Read-only mode</span><Pill tone="green">ENFORCED</Pill></div></div></Panel></div>}
    {special==='twin'&&<div className="module-grid"><Panel title="Infrastructure Fabric" kicker="PREDICTIVE MODEL" className="span-2 cinematic"><FabricMap labels={fabricLabels}/></Panel><Panel title="Coverage Radar" kicker="CONTROL SURFACE"><RadarField/></Panel><Panel title="Global Context" kicker="SIMULATION"><GlobeField primary={4} secondary={12}/></Panel></div>}
    {special==='soc'&&<div className="module-grid"><Panel title="Agent Wall" kicker="COORDINATED ANALYSIS"><AgentWall rows={agents}/></Panel><Panel title="Decision Timeline" kicker="SUPERVISOR"><ReasoningTimeline rows={reasoningRows}/></Panel><Panel title="Operational Fabric" kicker="LIVE MODEL" className="span-2"><FabricMap labels={fabricLabels}/></Panel></div>}
    {special==='intel'&&<div className="module-grid"><Panel title="Global Intelligence Field" kicker="X12 / SHARED SIGNALS"><GlobeField primary={Math.max(1,data.insights.insight_count??1)} secondary={18}/></Panel><Panel title="Signal Radar" kicker="CORRELATION"><RadarField/></Panel><Panel title="Intelligence Stream" kicker="LIVE FEED" className="span-2"><IntelligenceTicker items={intelItems}/></Panel></div>}
    {special==='research'&&<div className="module-grid"><Panel title="Evaluation Matrix" kicker="QUALITY LAB"><div className="research-score"><strong>{data.evaluation.result_count??0}</strong><span>recorded runs</span><div className="score-ring">95<small>%</small></div></div></Panel><Panel title="Reasoning Audit" kicker="REPRODUCIBILITY"><ReasoningTimeline rows={reasoningRows}/></Panel><Panel title="Benchmark Fabric" kicker="SYSTEM COMPARISON" className="span-2"><AgentWall rows={agents.map((x,i)=>[x[0],`benchmark scenario ${i+1}`,Math.max(68,x[2]-3),'cyan'])}/></Panel></div>}
    {special==='control'&&<div className="module-grid"><Panel title="Governance Core" kicker="POLICY CONTROL"><div className="control-core"><ReactorXL online/><strong>{data.control.tenant_count??0} TENANT</strong><span>{data.control.audit_decisions??0} audited decisions</span></div></Panel><Panel title="Authority Matrix" kicker="HUMAN APPROVAL"><div className="status-stack"><div><ShieldCheck/><span>Analysis</span><Pill tone="green">ALLOWED</Pill></div><div><LockKeyhole/><span>Validation</span><Pill tone="amber">APPROVAL</Pill></div><div><Database/><span>Retention</span><Pill tone="cyan">POLICY</Pill></div></div></Panel><Panel title="Decision Ledger" kicker="AUDIT TRAIL" className="span-2"><ReasoningTimeline rows={reasoningRows}/></Panel></div>}
    {special==='generic'&&<div className="module-grid"><Panel title="System Surface" kicker="LIVE CAPABILITIES"><div className="phase-grid">{Object.entries(data.status.phases||{}).map(([k,v])=><div className="phase-chip" key={k}><CircleDot size={12}/><strong>{k}</strong><span>{v}</span></div>)}</div></Panel><Panel title="Operational State" kicker="BACKEND TELEMETRY"><div className="status-stack"><div><ServerCog/><span>Backend API</span><Pill tone="green">ONLINE</Pill></div><div><Database/><span>Persistent stores</span><Pill tone="cyan">READY</Pill></div><div><BrainCircuit/><span>Agent fabric</span><Pill tone="violet">ACTIVE</Pill></div></div></Panel><Panel title="Interactive Fabric" kicker="LAB WORKSPACE" className="span-2"><FabricMap labels={fabricLabels}/></Panel></div>}
  </div>
}

export default function App(){
  const [view,setView]=useState<View>('command');const [data,setData]=useState<CommandData>(empty);const [loading,setLoading]=useState(true);const [selected,setSelected]=useState<CaseSummary|undefined>();const [overview,setOverview]=useState<any>(null);const [menu,setMenu]=useState(false);const [multi,setMulti]=useState(false)
  const refresh=async()=>{setLoading(true);const next=await loadCommandData();setData(next);setLoading(false)}
  useEffect(()=>{refresh();const id=setInterval(refresh,30000);return()=>clearInterval(id)},[])
  const healthy=data.health.status==='ok'&&data.ready.status==='ready';const title=useMemo(()=>nav.find(n=>n.id===view)?.label||'Sentinel X',[view])
  const openCase=async(c:CaseSummary)=>{setSelected(c);setView('cases');try{setOverview(await loadCaseOverview(c.case_id))}catch{setOverview(null)}}
  return <div className={`app-shell ${multi?'multi-mode':''}`}><div className="ambient ambient-one"/><div className="ambient ambient-two"/><div className="scanlines"/>
    <aside className={`sidebar ${menu?'sidebar-open':''}`}><div className="brand"><div className="brand-mark"><ShieldCheck size={18}/></div><div><strong>SENTINEL <b>X</b></strong><span>CYBER OPERATIONS LAB</span></div><button className="sidebar-close" onClick={()=>setMenu(false)}><X size={16}/></button></div><div className="nav-section-label">OPERATIONS</div><nav>{nav.map(({id,label,icon:Icon})=><button key={id} className={view===id?'active':''} onClick={()=>{setView(id);setMenu(false)}}><Icon size={16}/><span>{label}</span>{view===id&&<i/>}</button>)}</nav><div className="sidebar-foot"><div className="core-mini"><div className={`core-dot ${healthy?'ok':'bad'}`}/><div><strong>SENTINEL CORE</strong><span>{healthy?'Systems nominal':'Backend degraded'}</span></div></div><div className="build">UI 2.0 · BACKEND API 1.0</div></div></aside>
    <main className="main-shell"><header className="topbar"><button className="mobile-menu" onClick={()=>setMenu(true)}><Menu size={17}/></button><div className="breadcrumb"><span>SENTINEL X</span><ChevronRight size={11}/><strong>{title.toUpperCase()}</strong></div><div className="top-search"><Search size={15}/><input placeholder="Search cases, IOCs, assets, evidence..."/></div><div className="top-actions"><Pill tone={healthy?'green':'red'}>{healthy?'SYSTEM ONLINE':'DEGRADED'}</Pill><button className={loading?'spin':''} onClick={refresh}><RefreshCw size={15}/></button><button onClick={()=>setMulti(!multi)} className={multi?'active-tool':''}><Maximize2 size={15}/></button><button><Bell size={15}/><span className="notification-dot"/></button><div className="operator"><span>RR</span><div><strong>OPERATOR</strong><small>Lead Analyst</small></div></div></div></header>
      <div className="content">{view==='command'?<CommandCenter data={data} onSelectCase={openCase}/>:view==='cases'?<InvestigationLab selected={selected} overview={overview}/>:<LabView view={view} data={data}/>}</div>
      <div className="telemetry-footer"><span><i className="ok"/> CORE {healthy?'ONLINE':'DEGRADED'}</span><span>API {data.status.backend_api_version||'1.0'}</span><span>{data.status.generation||'X12'}</span><span>CASES {data.cases.length}</span><span>TWIN {Math.round((data.twin.coverage_ratio??0)*100)}%</span><span className="footer-live"><Activity size={10}/> LIVE TELEMETRY</span></div>
    </main>
  </div>
}
