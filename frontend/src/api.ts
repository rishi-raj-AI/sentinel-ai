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

const API_BASE = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8765').replace(/\/$/, '')

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { headers: { Accept: 'application/json' } })
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
