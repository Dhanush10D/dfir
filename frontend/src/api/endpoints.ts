import { apiFetch, apiGet, apiPost, apiRequest, ApiError } from './client'
import type {
  Alert,
  AlertDetail,
  AlertEvent,
  AttackRow,
  Bookmark,
  CaseDetail,
  Case,
  CustodyEntry,
  Entity,
  EntityDetail,
  EventDetail,
  EventPage,
  EventRow,
  Evidence,
  FacetValue,
  Graph,
  Histogram,
  Job,
  Note,
  NoteDetail,
  Page,
  ProcessTree,
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
}
