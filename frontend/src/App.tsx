import { useEffect, useMemo, useState } from 'react'
import {
  Activity, Aperture, Atom, Bell, Binary, Boxes, BrainCircuit, Bug, ChevronRight,
  CircleDot, CloudCog, Command, Cpu, Database, FlaskConical, Gauge, GitBranch,
  Globe2, Hexagon, KeyRound, Layers3, LockKeyhole, Network, Orbit, Radar, RefreshCw,
  Search, ServerCog, ShieldCheck, ShieldAlert, Sparkles, TerminalSquare, Waypoints,
} from 'lucide-react'
import { loadCaseOverview, loadCommandData, type CaseSummary } from './api'

type View = 'command' | 'cases' | 'soc' | 'intel' | 'graph' | 'appsec' | 'malware' | 'twin' | 'research' | 'control'

type CommandData = Awaited<ReturnType<typeof loadCommandData>>

const nav: { id: View; label: string; icon: any }[] = [
  { id: 'command', label: 'Command Center', icon: Command },
  { id: 'cases', label: 'Investigations', icon: Layers3 },
  { id: 'soc', label: 'SOC Operations', icon: Radar },
  { id: 'intel', label: 'Threat Intelligence', icon: Globe2 },
  { id: 'graph', label: 'Knowledge Graph', icon: GitBranch },
  { id: 'appsec', label: 'AppSec Lab', icon: Bug },
  { id: 'malware', label: 'Malware Lab', icon: Binary },
  { id: 'twin', label: 'Digital Twin', icon: Orbit },
  { id: 'research', label: 'Research Lab', icon: FlaskConical },
  { id: 'control', label: 'Control Plane', icon: LockKeyhole },
]

const empty: CommandData = {
  status: {}, cases: [], control: {}, twin: {}, evaluation: {}, insights: {}, health: {}, ready: {},
}

function Pill({ children, tone = 'cyan' }: { children: any; tone?: 'cyan' | 'violet' | 'amber' | 'red' | 'green' }) {
  return <span className={`pill pill-${tone}`}><span className="pill-dot" />{children}</span>
}

function Panel({ title, kicker, action, children, className = '' }: { title: string; kicker?: string; action?: any; children: any; className?: string }) {
  return <section className={`panel ${className}`}>
    <div className="panel-head">
      <div><div className="eyebrow">{kicker}</div><h3>{title}</h3></div>
      {action}
    </div>
    {children}
  </section>
}

function Metric({ label, value, sub, tone = 'cyan' }: { label: string; value: string | number; sub: string; tone?: string }) {
  return <div className={`metric metric-${tone}`}>
    <div className="metric-label">{label}</div>
    <div className="metric-value">{value}</div>
    <div className="metric-sub">{sub}</div>
  </div>
}

function Reactor({ active }: { active: boolean }) {
  return <div className={`reactor ${active ? 'reactor-active' : ''}`}>
    <div className="reactor-ring r1" /><div className="reactor-ring r2" /><div className="reactor-ring r3" />
    <div className="reactor-core"><BrainCircuit size={24} /></div>
  </div>
}

function TwinMap() {
  const nodes = [
    { x: 65, y: 120, label: 'IDENTITY', kind: 'identity' },
    { x: 205, y: 75, label: 'API GATEWAY', kind: 'service' },
    { x: 350, y: 145, label: 'APP CLUSTER', kind: 'service' },
    { x: 500, y: 82, label: 'PROD DB', kind: 'critical' },
    { x: 510, y: 220, label: 'CLOUD IAM', kind: 'identity' },
    { x: 315, y: 260, label: 'SOC SENSOR', kind: 'defense' },
    { x: 125, y: 260, label: 'EDGE', kind: 'service' },
  ]
  const edges = [[0,1],[1,2],[2,3],[2,4],[5,2],[6,1],[4,3]]
  return <div className="twin-map">
    <div className="grid-plane" />
    <svg viewBox="0 0 580 320" role="img" aria-label="Digital twin topology">
      {edges.map(([a,b], i) => <line key={i} x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y} className="twin-edge" />)}
      {nodes.map((n, i) => <g key={n.label} className={`twin-node twin-${n.kind}`}>
        <circle cx={n.x} cy={n.y} r="23" /><circle cx={n.x} cy={n.y} r="6" className="node-core" />
        <text x={n.x} y={n.y + 42} textAnchor="middle">{n.label}</text>
        {i === 2 && <circle cx={n.x} cy={n.y} r="34" className="pulse-circle" />}
      </g>)}
    </svg>
    <div className="map-badge"><Waypoints size={13}/> SIMULATION LAYER</div>
  </div>
}

function AgentStream() {
  const rows = [
    ['NETWORK ANALYST', 'Correlating flow evidence', 'ACTIVE', 'violet'],
    ['COUNTER-EVIDENCE', 'Testing alternate hypotheses', 'ACTIVE', 'cyan'],
    ['MALWARE ANALYST', 'Artifact queue synchronized', 'READY', 'green'],
    ['IDENTITY ANALYST', 'Privilege paths updated', 'READY', 'green'],
    ['SOC SUPERVISOR', 'Awaiting specialist consensus', 'WATCH', 'amber'],
  ]
  return <div className="agent-list">{rows.map(([name, task, state, tone]) => <div className="agent-row" key={name}>
    <div className="agent-avatar"><Cpu size={15}/></div><div className="agent-copy"><strong>{name}</strong><span>{task}</span></div><Pill tone={tone as any}>{state}</Pill>
  </div>)}</div>
}

function CommandCenter({ data, onSelectCase }: { data: CommandData; onSelectCase: (c: CaseSummary) => void }) {
  const healthy = data.health.status === 'ok' && data.ready.status === 'ready'
  const storeCount = Object.values(data.status.stores || {}).filter(Boolean).length
  return <>
    <div className="hero-strip">
      <div className="hero-copy"><div className="eyebrow">SENTINEL X / GLOBAL SECURITY FABRIC</div><h1>Cyber Command Center</h1><p>Evidence-grounded autonomous security operations across investigations, code, identity, cloud and simulated infrastructure.</p></div>
      <div className="hero-reactor"><Reactor active={healthy}/><div><strong>{healthy ? 'CORE ONLINE' : 'CORE DEGRADED'}</strong><span>{data.status.generation || 'X12'} · API {data.status.backend_api_version || '1.0'}</span></div></div>
    </div>
    <div className="metrics-grid">
      <Metric label="ACTIVE CASES" value={data.cases.length} sub="investigation workspaces" />
      <Metric label="DATA STORES" value={storeCount || 7} sub="persistent intelligence layers" tone="violet" />
      <Metric label="CONTROL TENANTS" value={data.control.tenant_count ?? 0} sub={`${data.control.audit_decisions ?? 0} policy decisions`} tone="amber" />
      <Metric label="TWIN COVERAGE" value={`${Math.round((data.twin.coverage_ratio ?? 0) * 100)}%`} sub="modeled control coverage" tone="green" />
    </div>
    <div className="command-grid">
      <Panel title="Operational Digital Twin" kicker="X8 / PREDICTIVE DEFENSE" className="span-2" action={<Pill tone="violet">LIVE MODEL</Pill>}><TwinMap /></Panel>
      <Panel title="Sentinel Core" kicker="MULTI-AGENT ORCHESTRATION" action={<Activity size={17} className="cyan"/>}><AgentStream /></Panel>
      <Panel title="Investigation Queue" kicker="EVIDENCE-FIRST CASES" action={<span className="panel-link">VIEW ALL <ChevronRight size={14}/></span>}>
        <div className="case-list">{data.cases.slice(0,5).map((c, i) => <button className="case-row" key={c.case_id} onClick={() => onSelectCase(c)}>
          <span className={`severity ${i === 0 ? 'sev-high' : 'sev-med'}`} />
          <span className="case-main"><strong>{c.case_id}</strong><small>{c.title || 'Security investigation'}</small></span>
          <span className="case-meta">{c.evidence_count ?? 0}<small>evidence</small></span><ChevronRight size={15}/>
        </button>)}{!data.cases.length && <div className="empty-state"><Aperture size={26}/><span>No active cases detected</span></div>}</div>
      </Panel>
      <Panel title="Intelligence Pulse" kicker="X12 / SHARED SIGNALS" action={<Pill tone="cyan">DE-IDENTIFIED</Pill>}>
        <div className="radar-card"><div className="radar-scope"><div className="sweep"/><div className="blip b1"/><div className="blip b2"/><div className="blip b3"/></div>
          <div className="radar-stats"><strong>{data.insights.insight_count ?? 0}</strong><span>shared insights</span><strong>{data.evaluation.result_count ?? 0}</strong><span>evaluation runs</span></div></div>
      </Panel>
      <Panel title="Security Fabric" kicker="BACKEND / X1—X12" className="span-2">
        <div className="phase-grid">{Object.entries(data.status.phases || {}).map(([k,v]) => <div className="phase-chip" key={k}><Hexagon size={13}/><strong>{k}</strong><span>{v}</span></div>)}</div>
      </Panel>
    </div>
  </>
}

function CaseDetail({ selected, overview }: { selected?: CaseSummary; overview: any }) {
  return <div className="workspace-grid">
    <Panel title={selected?.case_id || 'Investigation Lab'} kicker="CASE WORKSPACE" className="span-2">
      <div className="case-hero"><div><h2>{selected?.title || 'Select an investigation'}</h2><p>{overview?.brief?.executive_summary || 'Evidence, detections, graph relationships and AI reasoning converge here.'}</p></div><Pill tone={selected?.status === 'closed' ? 'green' : 'amber'}>{selected?.status || 'READY'}</Pill></div>
      <div className="evidence-grid"><Metric label="EVENTS" value={overview?.stats?.events ?? '—'} sub="timeline records"/><Metric label="EVIDENCE" value={overview?.stats?.evidence ?? selected?.evidence_count ?? '—'} sub="preserved items" tone="violet"/><Metric label="SIGMA" value={overview?.stats?.sigma_detections ?? '—'} sub="detections" tone="amber"/><Metric label="GRAPH" value={overview?.stats?.graph_nodes ?? '—'} sub="connected nodes" tone="green"/></div>
    </Panel>
    <Panel title="Evidence Graph" kicker="PROVENANCE MAP"><TwinMap/></Panel>
    <Panel title="AI Reasoning Console" kicker="GROUNDED COPILOT"><div className="reasoning-console"><div className="console-line"><span>01</span>Retrieve case evidence and structured detections</div><div className="console-line"><span>02</span>Build hypotheses and search counter-evidence</div><div className="console-line"><span>03</span>Verify every factual claim against source IDs</div><div className="console-line active"><span>04</span>Await investigator objective…</div></div></Panel>
  </div>
}

function ModuleView({ view, data }: { view: View; data: CommandData }) {
  const cfg: Record<string, [string,string,any,string]> = {
    soc: ['Autonomous SOC', 'Multi-agent defensive analysis and evidence-grounded triage.', Radar, 'X9 SECURITY FUSION'],
    intel: ['Threat Intelligence', 'Cyber knowledge, generalized insights and source-aware intelligence.', Globe2, 'X2 + X12 INTELLIGENCE'],
    graph: ['Knowledge Graph', 'Traverse vulnerabilities, products, evidence, identities and relationships.', Network, 'X2 KNOWLEDGE INTELLIGENCE'],
    appsec: ['AppSec Laboratory', 'Static code, dependency, secret and supply-chain analysis.', Bug, 'X7 SOFTWARE SECURITY'],
    malware: ['Reverse Engineering Lab', 'Artifact hashing, format analysis, indicators and behavioral references.', Binary, 'X5 ARTIFACT INTELLIGENCE'],
    twin: ['Digital Twin', 'Predictive infrastructure modeling, path simulation and control coverage.', Orbit, 'X8 SIMULATION ENGINE'],
    research: ['Research & Evaluation Lab', 'Benchmark Sentinel agents with reproducible scenarios and quality metrics.', FlaskConical, 'X11 EVALUATION LAB'],
    control: ['Enterprise Control Plane', 'Tenant policy, autonomy ceilings, approvals and auditable decisions.', ShieldCheck, 'X10 GOVERNANCE'],
  }
  const [title, subtitle, Icon, kicker] = cfg[view] || cfg.soc
  return <div className="module-page">
    <div className="module-hero"><div className="module-icon"><Icon size={30}/></div><div><div className="eyebrow">{kicker}</div><h1>{title}</h1><p>{subtitle}</p></div></div>
    <div className="module-grid">
      <Panel title="System Surface" kicker="LIVE CAPABILITIES"><div className="phase-grid">{Object.entries(data.status.phases || {}).map(([k,v]) => <div className="phase-chip" key={k}><CircleDot size={12}/><strong>{k}</strong><span>{v}</span></div>)}</div></Panel>
      <Panel title="Operational State" kicker="BACKEND TELEMETRY"><div className="status-stack"><div><ServerCog/><span>Backend API</span><Pill tone="green">ONLINE</Pill></div><div><Database/><span>Persistent stores</span><Pill tone="cyan">READY</Pill></div><div><BrainCircuit/><span>Agent fabric</span><Pill tone="violet">ACTIVE</Pill></div><div><ShieldCheck/><span>Policy enforcement</span><Pill tone="green">ENABLED</Pill></div></div></Panel>
      <Panel title="Lab Workspace" kicker="INTERACTIVE SURFACE" className="span-2"><div className="lab-placeholder"><div className="lab-rings"><Atom size={46}/></div><h2>{title} interface connected</h2><p>The module shell is ready for deeper workflow-specific controls while preserving the common Sentinel X design language and backend contract.</p><button className="primary-button"><Sparkles size={15}/> INITIALIZE WORKSPACE</button></div></Panel>
    </div>
  </div>
}

export default function App() {
  const [view, setView] = useState<View>('command')
  const [data, setData] = useState<CommandData>(empty)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<CaseSummary | undefined>()
  const [overview, setOverview] = useState<any>(null)
  const [menu, setMenu] = useState(false)

  const refresh = async () => { setLoading(true); const next = await loadCommandData(); setData(next); setLoading(false) }
  useEffect(() => { refresh(); const id = setInterval(refresh, 30000); return () => clearInterval(id) }, [])
  const healthy = data.health.status === 'ok' && data.ready.status === 'ready'
  const title = useMemo(() => nav.find(n => n.id === view)?.label || 'Sentinel X', [view])

  const openCase = async (c: CaseSummary) => {
    setSelected(c); setView('cases');
    try { setOverview(await loadCaseOverview(c.case_id)) } catch { setOverview(null) }
  }

  return <div className="app-shell">
    <div className="ambient ambient-one"/><div className="ambient ambient-two"/><div className="scanlines"/>
    <aside className={`sidebar ${menu ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldAlert size={22}/></div><div><strong>SENTINEL <b>X</b></strong><span>CYBER OPERATIONS LAB</span></div></div>
      <div className="nav-section-label">OPERATIONS</div>
      <nav>{nav.map(n => <button key={n.id} className={view === n.id ? 'active' : ''} onClick={() => {setView(n.id); setMenu(false)}}><n.icon size={17}/><span>{n.label}</span>{view === n.id && <i/>}</button>)}</nav>
      <div className="sidebar-foot"><div className="core-mini"><Reactor active={healthy}/><div><strong>SENTINEL CORE</strong><span>{healthy ? 'Systems nominal' : 'Check backend'}</span></div></div><div className="build">X12 / API 1.0 / LAB BUILD</div></div>
    </aside>

    <main className="main-shell">
      <header className="topbar">
        <button className="mobile-menu" onClick={() => setMenu(!menu)}><Boxes size={19}/></button>
        <div className="breadcrumb"><span>SENTINEL X</span><ChevronRight size={13}/><strong>{title.toUpperCase()}</strong></div>
        <div className="top-search"><Search size={15}/><input placeholder="Search cases, IOCs, assets, evidence…"/></div>
        <div className="top-actions"><Pill tone={healthy ? 'green' : 'red'}>{healthy ? 'SYSTEM ONLINE' : 'DEGRADED'}</Pill><button className={loading ? 'spin' : ''} onClick={refresh}><RefreshCw size={16}/></button><button><Bell size={16}/><span className="notification-dot"/></button><div className="operator"><span>RR</span><div><strong>OPERATOR</strong><small>Lead Analyst</small></div></div></div>
      </header>
      <div className="content">
        {view === 'command' && <CommandCenter data={data} onSelectCase={openCase}/>} 
        {view === 'cases' && <CaseDetail selected={selected || data.cases[0]} overview={overview}/>} 
        {!['command','cases'].includes(view) && <ModuleView view={view} data={data}/>} 
      </div>
      <footer className="telemetry-bar"><span><Activity size={12}/> TELEMETRY STREAM</span><span className="telemetry-pulse">●</span><span>CORE {healthy ? 'NOMINAL' : 'DEGRADED'}</span><span>·</span><span>{data.cases.length} CASES</span><span>·</span><span>{data.evaluation.result_count ?? 0} EVAL RUNS</span><span className="telemetry-right">ENCRYPTED SESSION // {new Date().toLocaleTimeString()}</span></footer>
    </main>
  </div>
}
