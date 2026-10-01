import { apiFetch, apiGet, apiPost, apiRequest, ApiError } from './client'
import type {
  AiIndex,
  AiInteraction,
  AiInteractionDetail,
  AiResult,
  AiStatus,
  ActionRequest,
  Alert,
  AlertDetail,
  AlertEvent,
  AppNotification,
  AttackRow,
  Bookmark,
  CaseDetail,
  Case,
  CustodyEntry,
  DeliveryLog,
  EnrichmentEntry,
  Entity,
  EntityDetail,
  EventDetail,
  EventPage,
  EventRow,
  Evidence,
  FacetValue,
  Graph,
  Histogram,
  Integration,
  IntegrationType,
  Job,
  Note,
  NoteDetail,
  Page,
  Playbook,
  PlaybookRun,
  PlaybookRunDetail,
  ProcessTree,
  Report,
  ReportDetail,
  ReportFinding,
  ReportKind,
  ReportVerify,
  RunPlan,
  StepOp,
  StepPlan,
  Summary,
  VerifyResult,
} from './types'

const enc = encodeURIComponent

export interface QueryScope {
  query: string
  from?: string
  to?: string
}

function scope(s: QueryScope): Record<string, string> {
  const body: Record<string, string> = { query: s.query }
  if (s.from) body.from = s.from
  if (s.to) body.to = s.to
  return body
}

const FILENAME = /filename="([A-Za-z0-9._-]{1,200})"/

async function blobResult(res: Response, fallback: string): Promise<{ blob: Blob; filename: string }> {
  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as { error?: { code?: string; message?: string } } | null
    throw new ApiError(res.status, body?.error?.code ?? 'download_failed', body?.error?.message ?? `HTTP ${res.status}`)
  }
  const match = FILENAME.exec(res.headers.get('Content-Disposition') ?? '')
  return { blob: await res.blob(), filename: match?.[1] ?? fallback }
}

/** Save a blob through a temporary object URL (the name comes from a strict allow-list regex). */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const api = {
  cases: (signal?: AbortSignal) => apiGet<Page<Case>>('/cases?limit=200', { signal }),
  createCase: (title: string, description: string) =>
    apiPost<CaseDetail>('/cases', { title, description: description || null }),
  caseDetail: (id: string, signal?: AbortSignal) =>
    apiGet<CaseDetail>(`/cases/${enc(id)}`, { signal }),
  summary: (id: string, signal?: AbortSignal) =>
    apiGet<Summary>(`/cases/${enc(id)}/summary`, { signal }),

  evidence: (id: string, signal?: AbortSignal) =>
    apiGet<Page<Evidence>>(`/cases/${enc(id)}/evidence?limit=200`, { signal }),
  custody: (evidenceId: string, signal?: AbortSignal) =>
    apiGet<{ entries: CustodyEntry[] }>(`/evidence/${enc(evidenceId)}/custody`, { signal }),
  verify: (evidenceId: string) => apiPost<VerifyResult>(`/evidence/${enc(evidenceId)}/verify`),
  process: (evidenceId: string) =>
    apiPost<{ jobs: Job[] }>(`/evidence/${enc(evidenceId)}/process`, {}),
  jobs: (id: string, signal?: AbortSignal) =>
    apiGet<Page<Job>>(`/cases/${enc(id)}/jobs?limit=50`, { signal }),
  async upload(caseId: string, file: File, kind: string): Promise<Evidence> {
    const created = await apiPost<{ evidence: Evidence }>(`/cases/${enc(caseId)}/evidence`, {
      kind,
      original_name: file.name.slice(0, 1024) || 'upload.bin',
      size_bytes: file.size,
    })
    const id = created.evidence.id
    // Raw streaming PUT (the API hashes while it stores); the auth wrapper adds the token.
    const res = await apiFetch('PUT', `/evidence/${enc(id)}/upload`, {
      headers: { 'Content-Type': 'application/octet-stream' },
      rawBody: file,
    })
    if (!res.ok) throw new ApiError(res.status, 'upload_failed', `Upload failed (HTTP ${res.status})`)
    const done = await apiPost<{ ok: boolean; evidence: Evidence }>(
      `/evidence/${enc(id)}/finalize`,
    )
    return done.evidence
  },

  search: (caseId: string, s: QueryScope, cursor: string | null, signal?: AbortSignal) =>
    apiPost<EventPage>(
      `/cases/${enc(caseId)}/events/search`,
      { ...scope(s), limit: 100, ...(cursor ? { cursor } : {}) },
      signal,
    ),
  histogram: (caseId: string, s: QueryScope, signal?: AbortSignal) =>
    apiPost<Histogram>(`/cases/${enc(caseId)}/events/histogram`, { ...scope(s), buckets: 60 }, signal),
  facets: (caseId: string, s: QueryScope, fields: string[], signal?: AbortSignal) =>
    apiPost<{ fields: Record<string, FacetValue[]> }>(
      `/cases/${enc(caseId)}/events/facets`,
      { ...scope(s), fields, size: 8 },
      signal,
    ),
  event: (caseId: string, eventId: string, signal?: AbortSignal) =>
    apiGet<EventDetail>(`/cases/${enc(caseId)}/events/${enc(eventId)}`, { signal }),
  context: (caseId: string, eventId: string, minutes: number) =>
    apiPost<{ anchor: EventRow; items: EventRow[] }>(`/cases/${enc(caseId)}/events/context`, {
      event_id: eventId,
      minutes,
    }),
  async exportEvents(caseId: string, s: QueryScope, format: 'csv' | 'json'): Promise<Blob> {
    const res = await apiFetch('POST', `/cases/${enc(caseId)}/events/export`, {
      body: { ...scope(s), format },
    })
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null
      throw new ApiError(res.status, 'export_failed', body?.error?.message ?? `HTTP ${res.status}`)
    }
    return res.blob()
  },

  alerts: (caseId: string, params: URLSearchParams, signal?: AbortSignal) =>
    apiGet<Page<Alert>>(`/cases/${enc(caseId)}/alerts?${params.toString()}`, { signal }),
  alert: (alertId: string, signal?: AbortSignal) =>
    apiGet<AlertDetail>(`/alerts/${enc(alertId)}`, { signal }),
  alertEvents: (alertId: string, signal?: AbortSignal) =>
    apiGet<Page<AlertEvent>>(`/alerts/${enc(alertId)}/events?limit=100`, { signal }),
  updateAlert: (alertId: string, body: Record<string, unknown>) =>
    apiRequest<AlertDetail>('PATCH', `/alerts/${enc(alertId)}`, { body }),
  attack: (caseId: string, signal?: AbortSignal) =>
    apiGet<AttackRow[]>(`/cases/${enc(caseId)}/attack`, { signal }),

  notes: (caseId: string, includeRetracted: boolean, signal?: AbortSignal) =>
    apiGet<Page<Note>>(
      `/cases/${enc(caseId)}/notes?include_retracted=${includeRetracted ? 'true' : 'false'}`,
      { signal },
    ),
  note: (noteId: string, signal?: AbortSignal) =>
    apiGet<NoteDetail>(`/notes/${enc(noteId)}`, { signal }),
  createNote: (caseId: string, body: Record<string, unknown>) =>
    apiPost<Note>(`/cases/${enc(caseId)}/notes`, body),
  editNote: (noteId: string, body_md: string, expected_version: number) =>
    apiRequest<NoteDetail>('PATCH', `/notes/${enc(noteId)}`, {
      body: { body_md, expected_version },
    }),
  retractNote: (noteId: string, expected_version: number) =>
    apiPost<NoteDetail>(`/notes/${enc(noteId)}/retract`, { expected_version }),
  bookmarks: (caseId: string, signal?: AbortSignal) =>
    apiGet<Bookmark[]>(`/cases/${enc(caseId)}/bookmarks`, { signal }),
  addBookmark: (caseId: string, target_type: string, target_id: string) =>
    apiPost<Bookmark>(`/cases/${enc(caseId)}/bookmarks`, { target_type, target_id }),
  deleteBookmark: (caseId: string, id: string) =>
    apiRequest<void>('DELETE', `/cases/${enc(caseId)}/bookmarks/${enc(id)}`),

  entities: (caseId: string, type: string, q: string, signal?: AbortSignal) => {
    const p = new URLSearchParams({ limit: '100' })
    if (type) p.set('type', type)
    if (q) p.set('q', q)
    return apiGet<Page<Entity>>(`/cases/${enc(caseId)}/entities?${p.toString()}`, { signal })
  },
  entity: (entityId: string, signal?: AbortSignal) =>
    apiGet<EntityDetail>(`/entities/${enc(entityId)}`, { signal }),
  graph: (caseId: string, entityId: string | null, signal?: AbortSignal) => {
    const p = new URLSearchParams({ max_nodes: '60', max_edges: '300' })
    if (entityId) p.set('entity_id', entityId)
    return apiGet<Graph>(`/cases/${enc(caseId)}/graph?${p.toString()}`, { signal })
  },
  processTree: (caseId: string, host: string, signal?: AbortSignal) =>
    apiGet<ProcessTree>(
      `/cases/${enc(caseId)}/process-tree?${new URLSearchParams({ host }).toString()}`,
      { signal },
    ),

  aiStatus: (signal?: AbortSignal) => apiGet<AiStatus>('/ai/status', { signal }),
  aiNlq: (caseId: string, question: string) =>
    apiPost<AiResult>('/ai/nlq', { case_id: caseId, question }),
  aiExplainAlert: (alertId: string) => apiPost<AiResult>(`/ai/alerts/${enc(alertId)}/explain`),
  aiNarrative: (caseId: string, body: Record<string, string>) =>
    apiPost<AiResult>(`/ai/cases/${enc(caseId)}/narrative`, body),
  aiChat: (caseId: string, question: string) =>
    apiPost<AiResult>(`/ai/cases/${enc(caseId)}/chat`, { question }),
  aiScript: (caseId: string, text: string) =>
    apiPost<AiResult>('/ai/script/explain', { case_id: caseId, text }),
  aiIndex: (caseId: string, signal?: AbortSignal) =>
    apiGet<AiIndex>(`/ai/cases/${enc(caseId)}/index`, { signal }),
  aiSetCase: (caseId: string, aiEnabled: boolean) =>
    apiRequest<{ ai_enabled: boolean }>('PUT', `/ai/cases/${enc(caseId)}/settings`, {
      body: { ai_enabled: aiEnabled },
    }),
  aiInteractions: (caseId: string, signal?: AbortSignal) =>
    apiGet<Page<AiInteraction>>(`/ai/interactions?case_id=${enc(caseId)}&limit=50`, { signal }),
  aiInteraction: (id: string, signal?: AbortSignal) =>
    apiGet<AiInteractionDetail>(`/ai/interactions/${enc(id)}`, { signal }),
  aiReview: (id: string, decision: 'accept' | 'reject', acknowledge: boolean, note: string) =>
    apiPost<AiInteractionDetail>(`/ai/interactions/${enc(id)}/review`, {
      decision,
      acknowledge_warnings: acknowledge,
      note: note || null,
    }),
  reports: (caseId: string, signal?: AbortSignal) =>
    apiGet<{ items: Report[] }>(`/cases/${enc(caseId)}/reports`, { signal }),
  report: (id: string, signal?: AbortSignal) => apiGet<ReportDetail>(`/reports/${enc(id)}`, { signal }),
  createReport: (caseId: string, kind: ReportKind, title: string) =>
    apiPost<ReportDetail>(`/cases/${enc(caseId)}/reports`, { kind, title: title || null }),
  updateReport: (
    id: string,
    body: { expected_revision: number; title?: string; sections?: Record<string, string>; findings?: ReportFinding[] },
  ) => apiRequest<ReportDetail>('PATCH', `/reports/${enc(id)}`, { body }),
  reportAction: (id: string, action: 'qa' | 'approve' | 'sign' | 'versions') =>
    apiPost<ReportDetail>(`/reports/${enc(id)}/${action}`),
  submitReport: (id: string, expected_revision: number) =>
    apiPost<ReportDetail>(`/reports/${enc(id)}/submit`, { expected_revision }),
  returnReport: (id: string, reason: string) => apiPost<ReportDetail>(`/reports/${enc(id)}/return`, { reason }),
  verifyReport: (id: string) => apiGet<ReportVerify>(`/reports/${enc(id)}/verify`),
  applyAiDraft: (id: string, section: string, interaction_id: string, expected_revision: number) =>
    apiPost<ReportDetail>(`/reports/${enc(id)}/sections/${enc(section)}/apply-ai`, {
      interaction_id,
      expected_revision,
    }),
  aiDraftSection: (id: string, section: string) => apiPost<AiResult>(`/ai/reports/${enc(id)}/draft`, { section }),
  /** Report HTML as text, shown only inside a sandboxed iframe (never injected into the page). */
  async reportPreview(id: string, signal?: AbortSignal): Promise<string> {
    const res = await apiFetch('GET', `/reports/${enc(id)}/preview`, { signal, headers: { Accept: 'text/html' } })
    if (!res.ok) throw new ApiError(res.status, 'preview_failed', `Preview failed (HTTP ${res.status})`)
    return res.text()
  },
  async reportDownload(id: string, format: string): Promise<{ blob: Blob; filename: string }> {
    const res = await apiFetch('GET', `/reports/${enc(id)}/download?format=${enc(format)}`)
    return blobResult(res, `report.${format}`)
  },
  async exportPackage(evidenceId: string): Promise<{ blob: Blob; filename: string }> {
    const res = await apiFetch('POST', `/evidence/${enc(evidenceId)}/export-package`)
    return blobResult(res, 'evidence_package.zip')
  },
  // ---- Phase 9: response
  playbooks: (signal?: AbortSignal) => apiGet<{ items: Playbook[] }>('/playbooks', { signal }),
  alertPlaybooks: (alertId: string, signal?: AbortSignal) =>
    apiGet<{ items: Playbook[] }>(`/alerts/${enc(alertId)}/playbooks`, { signal }),
  playbookRuns: (caseId: string, signal?: AbortSignal) =>
    apiGet<{ items: PlaybookRun[] }>(`/cases/${enc(caseId)}/playbook-runs`, { signal }),
  playbookRun: (runId: string, signal?: AbortSignal) =>
    apiGet<PlaybookRunDetail>(`/playbook-runs/${enc(runId)}`, { signal }),
  startRun: (caseId: string, playbookId: string, alertId: string | null) =>
    apiPost<PlaybookRunDetail>(`/cases/${enc(caseId)}/playbook-runs`, {
      playbook_id: playbookId,
      alert_id: alertId,
    }),
  planRun: (caseId: string, playbookId: string, alertId: string | null) =>
    apiPost<RunPlan>(`/cases/${enc(caseId)}/playbook-runs`, {
      playbook_id: playbookId,
      alert_id: alertId,
      dry_run: true,
    }),
  stepOp: (
    runId: string,
    stepKey: string,
    body: { op: StepOp; notes?: string | null; params?: Record<string, string | number> },
  ) =>
    apiRequest<PlaybookRunDetail>('PATCH', `/playbook-runs/${enc(runId)}/steps/${enc(stepKey)}`, { body }),
  planStep: (runId: string, stepKey: string, op: StepOp, params: Record<string, string | number>) =>
    apiRequest<StepPlan>('PATCH', `/playbook-runs/${enc(runId)}/steps/${enc(stepKey)}`, {
      body: { op, params, dry_run: true },
    }),
  cancelRun: (runId: string, reason: string) =>
    apiPost<PlaybookRunDetail>(`/playbook-runs/${enc(runId)}/cancel`, { reason }),
  actionRequests: (caseId: string, signal?: AbortSignal) =>
    apiGet<{ items: ActionRequest[] }>(`/cases/${enc(caseId)}/action-requests`, { signal }),
  approveAction: (requestId: string) => apiPost<ActionRequest>(`/action-requests/${enc(requestId)}/approve`, {}),
  rejectAction: (requestId: string, reason: string) =>
    apiPost<ActionRequest>(`/action-requests/${enc(requestId)}/reject`, { reason }),
  enrichIocs: (caseId: string) =>
    apiPost<{ results: EnrichmentEntry[]; counts: Record<string, number>; truncated: boolean }>(
      `/cases/${enc(caseId)}/iocs/enrich`,
      {},
    ),
  enrichments: (caseId: string, signal?: AbortSignal) =>
    apiGet<{ items: EnrichmentEntry[] }>(`/cases/${enc(caseId)}/enrichments`, { signal }),
  // ---- Phase 9: integrations (admin) and notifications
  integrations: (signal?: AbortSignal) =>
    apiGet<{ items: Integration[]; secrets_available: boolean }>('/integrations', { signal }),
  createIntegration: (body: {
    type: IntegrationType
    name: string
    config: Record<string, unknown>
    secret?: Record<string, string>
    enabled: boolean
    case_id?: string
  }) => apiPost<Integration>('/integrations', body),
  updateIntegration: (
    id: string,
    body: { enabled?: boolean; secret?: Record<string, string>; config?: Record<string, unknown> },
  ) => apiRequest<Integration>('PATCH', `/integrations/${enc(id)}`, { body }),
  testIntegration: (id: string) =>
    apiPost<{ event_id: string; queued: boolean }>(`/integrations/${enc(id)}/test`),
  deliveries: (id: string, signal?: AbortSignal) =>
    apiGet<DeliveryLog>(`/integrations/${enc(id)}/deliveries`, { signal }),
  notifications: (signal?: AbortSignal) =>
    apiGet<{ items: AppNotification[]; unread: number }>('/notifications?limit=100', { signal }),
  readNotification: (id: string) => apiPost<AppNotification>(`/notifications/${enc(id)}/read`),
  readAllNotifications: () => apiPost<void>('/notifications/read-all'),
  aiFeedback: (id: string, value: -1 | 0 | 1) =>
    apiPost<AiInteraction>(`/ai/interactions/${enc(id)}/feedback`, { value }),
}
