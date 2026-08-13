export type PlatformStatus = {
  platform?: string
  generation?: string
  backend_api_version?: string
  backend_ui_ready?: boolean
  phases?: Record<string, string>
  evaluation?: { version?: string; scenario_count?: number; result_count?: number }
  shared_insights?: { version?: string; insight_count?: number; minimum_sources?: number }
  stores?: Record<string, boolean>
  policy?: Record<string, boolean>
}

export type CaseSummary = {
  case_id: string
  title?: string
  status?: string
  created_at?: string
  evidence_count?: number
}

export type ControlStats = { version?: string; tenant_count?: number; audit_decisions?: number }
export type TwinCoverage = { controlled_edges?: number; uncontrolled_edges?: number; coverage_ratio?: number }
export type EvalSummary = { version?: string; scenario_count?: number; result_count?: number }
export type InsightStats = { version?: string; insight_count?: number; minimum_sources?: number }

export type ToolRow = {
  tool_id: string
  name: string
  pack?: string
  installed?: boolean
  compatible?: boolean
  ready?: boolean
  version?: string | null
  profiles?: string[]
  one_click_install?: boolean
  install_manager?: string | null
  install_description?: string | null
  error?: string | null
}

export type ToolInventory = {
  version?: string
  manager_version?: string
  ready_count?: number
  total_count?: number
  required_ready?: number
  required_total?: number
  packs?: Record<string, string[]>
  tools?: ToolRow[]
}

export type ToolPlan = {
  version?: string
  objective?: string
  required_tools?: Array<ToolRow & { reason?: string; status?: string }>
  missing_or_incompatible?: Array<ToolRow & { reason?: string; status?: string }>
  ready_to_execute?: boolean
  next_action?: string
  policy?: Record<string, boolean>
}

export type CopilotStatus = {
  configured?: boolean
  mode?: string
  model?: string | null
  endpoint_configured?: boolean
  grounding?: string
}

export type CopilotReply = {
  answer?: string
  mode?: string
  model?: string | null
  source_count?: number
  sources?: Array<{ source_id?: string; kind?: string; title?: string }>
}

export type InvestigationRun = {
  run_id?: string
  objective?: string
  overall_confidence?: string
  overall_confidence_percent?: number
  leading_hypothesis?: { statement?: string }
  hypotheses?: Array<{ id?: string; statement?: string; confidence?: string; confidence_percent?: number }>
  recommended_actions?: string[]
  notebook?: Array<{ step?: string; timestamp?: string; status?: string }>
}

const API_BASE = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8765').replace(/\/$/, '')

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { headers: { Accept: 'application/json' } })
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  })
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`)
  return response.json() as Promise<T>
}

export async function loadCommandData() {
  const safe = async <T>(path: string, fallback: T): Promise<T> => {
    try { return await get<T>(path) } catch { return fallback }
  }

  const [status, cases, control, twin, evaluation, insights, health, ready] = await Promise.all([
    safe<PlatformStatus>('/api/x/status', {}),
    safe<CaseSummary[]>('/api/cases', []),
    safe<ControlStats>('/api/x/control/stats', {}),
    safe<TwinCoverage>('/api/x/twin/coverage', {}),
    safe<EvalSummary>('/api/x/evaluation/summary', {}),
    safe<InsightStats>('/api/x/insights/stats', {}),
    safe<{ status?: string }>('/healthz', {}),
    safe<{ status?: string; checks?: Record<string, boolean> }>('/readyz', {}),
  ])

  return { status, cases, control, twin, evaluation, insights, health, ready }
}

export async function loadCaseOverview(caseId: string) {
  return get<any>(`/api/cases/${encodeURIComponent(caseId)}/overview`)
}

export async function loadCaseTimeline(caseId: string, limit = 250) {
  return get<any>(`/api/cases/${encodeURIComponent(caseId)}/timeline?limit=${limit}`)
}

export async function loadCaseGraph(caseId: string) {
  return get<any>(`/api/cases/${encodeURIComponent(caseId)}/graph?max_nodes=120&max_edges=240`)
}

export async function loadCaseDetections(caseId: string) {
  return get<any>(`/api/cases/${encodeURIComponent(caseId)}/detections`)
}

export async function loadCopilotStatus() {
  return get<CopilotStatus>('/api/copilot/status')
}

export async function askCaseCopilot(caseId: string, question: string) {
  return post<CopilotReply>(`/api/cases/${encodeURIComponent(caseId)}/chat`, { question })
}

export async function listInvestigations(caseId: string) {
  return get<InvestigationRun[]>(`/api/cases/${encodeURIComponent(caseId)}/investigations`)
}

export async function loadInvestigation(caseId: string, runId: string) {
  return get<InvestigationRun>(`/api/cases/${encodeURIComponent(caseId)}/investigations/${encodeURIComponent(runId)}`)
}

export async function runInvestigation(caseId: string, objective: string, maxItems = 25) {
  return post<InvestigationRun>(`/api/cases/${encodeURIComponent(caseId)}/investigations`, { objective, max_items: maxItems })
}

export async function loadToolInventory() {
  return get<ToolInventory>('/api/x/tools')
}

export async function planTools(objective: string) {
  return post<ToolPlan>('/api/x/tools/plan', { objective })
}
