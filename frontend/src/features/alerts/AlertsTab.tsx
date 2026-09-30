import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { Alert, EventRow } from '@/api/types'
import { Button, ErrorMessage, inputClass, Loading, Panel, SeverityChip } from '@/components/ui'
import { AlertAiPanel } from '@/features/ai/AlertAiPanel'
import { useCase } from '@/features/cases/CaseContext'
import { EventDrawer } from '@/features/explorer/EventDrawer'
import { EventTable } from '@/features/explorer/EventTable'
import { formatUtc } from '@/lib/format'

/** Mirror of the server lifecycle (services/alerts.py); the server validates every change. */
const TRANSITIONS: Record<string, string[]> = {
  new: ['triaged', 'investigating', 'false_positive'],
  triaged: ['investigating', 'true_positive', 'false_positive'],
  investigating: ['true_positive', 'false_positive', 'triaged'],
  true_positive: ['closed', 'investigating'],
  false_positive: ['closed', 'investigating'],
  closed: ['investigating'],
}
const NEEDS_REASON = new Set(['true_positive', 'false_positive', 'closed'])

function StatusControl({ alert }: { alert: Alert }) {
  const { caseId } = useCase()
  const client = useQueryClient()
  const options = TRANSITIONS[alert.status] ?? []
  const [target, setTarget] = useState(options[0] ?? '')
  const [reason, setReason] = useState('')
  const change = useMutation({
    mutationFn: () =>
      api.updateAlert(alert.id, { status: target, reason: reason || null, expected_status: alert.status }),
    onSuccess: () => {
      setReason('')
      void client.invalidateQueries({ queryKey: ['alerts', caseId] })
      void client.invalidateQueries({ queryKey: ['alert', alert.id] })
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    change.mutate()
  }
  const reasonNeeded = NEEDS_REASON.has(target) || alert.status === 'closed'
  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Change alert status">
      <label className="text-sm">
        <span className="mb-1 block font-medium">New status</span>
        <select className={inputClass} value={target} onChange={(e) => setTarget(e.target.value)}>
          {options.map((o) => (
            <option key={o}>{o}</option>
          ))}
        </select>
      </label>
      <label className="text-sm">
        <span className="mb-1 block font-medium">Reason{reasonNeeded ? ' (required)' : ''}</span>
        <input className={inputClass} value={reason} maxLength={2000} required={reasonNeeded} onChange={(e) => setReason(e.target.value)} />
      </label>
      <Button type="submit" variant="primary" disabled={change.isPending || !target}>
        Update
      </Button>
      <ErrorMessage error={change.error} />
    </form>
  )
}

function AlertDetailPane({ alertId }: { alertId: string }) {
  const { can } = useCase()
  const detail = useQuery({ queryKey: ['alert', alertId], queryFn: ({ signal }) => api.alert(alertId, signal) })
  const events = useQuery({
    queryKey: ['alert-events', alertId],
    queryFn: ({ signal }) => api.alertEvents(alertId, signal),
  })
  const [open, setOpen] = useState<EventRow | null>(null)
  if (detail.isPending) return <Loading />
  if (detail.error) return <ErrorMessage error={detail.error} />
  const a = detail.data
  const linked = (events.data?.items ?? []).flatMap((l) => (l.event ? [l.event] : []))
  return (
    <div className="space-y-3">
      <div>
        <h3 className="font-semibold">{a.title}</h3>
        <p className="text-sm">
          <SeverityChip severity={a.severity} /> {a.status}
          {a.stale && ' (stale)'} · risk {a.risk_score} · {a.rule_id} · host {a.host ?? '-'} · user{' '}
          {a.user ?? '-'}
        </p>
        <p className="text-xs text-slate-500">
          {formatUtc(a.first_seen)} → {formatUtc(a.last_seen)} · {a.event_count} events ·{' '}
          {a.attack_tags.join(', ')}
        </p>
        {a.status_reason && <p className="text-sm">Reason: {a.status_reason}</p>}
      </div>
      {can('alert:update') && <StatusControl key={a.status} alert={a} />}
      {can('ai:use') && <AlertAiPanel key={a.id} alertId={a.id} />}
      <section aria-label="Alert history">
        <h4 className="text-sm font-medium">History</h4>
        <ul className="text-xs">
          {a.history.map((h) => (
            <li key={h.id}>
              {formatUtc(h.ts)} {h.action} {h.from_status ?? ''} → {h.to_status ?? ''} {h.reason ?? ''}
            </li>
          ))}
        </ul>
      </section>
      <section aria-label="Linked events">
        <h4 className="text-sm font-medium">Linked events</h4>
        {events.isPending ? <Loading /> : <EventTable events={linked} onOpen={setOpen} caption="Linked events" />}
      </section>
      {open && <EventDrawer event={open} onClose={() => setOpen(null)} onPivot={() => setOpen(null)} />}
    </div>
  )
}

export function AlertsTab() {
  const { caseId } = useCase()
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const params = new URLSearchParams({ limit: '200' })
  if (status) params.set('status', status)
  if (severity) params.set('severity', severity)
  const list = useQuery({
    queryKey: ['alerts', caseId, status, severity],
    queryFn: ({ signal }) => api.alerts(caseId, params, signal),
  })
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="Alerts">
        <div className="mb-2 flex flex-wrap gap-2">
          <label className="text-sm">
            <span className="mr-1">Status</span>
            <select className={inputClass} value={status} onChange={(e) => setStatus(e.target.value)}>
              <option value="">any</option>
              {Object.keys(TRANSITIONS).map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label className="text-sm">
            <span className="mr-1">Min severity</span>
            <select className={inputClass} value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">any</option>
              {['info', 'low', 'medium', 'high', 'critical'].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
        </div>
        {list.isPending && <Loading />}
        <ErrorMessage error={list.error} />
        <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
          {list.data?.items.map((a) => (
            <li key={a.id}>
              <button
                type="button"
                aria-pressed={selected === a.id}
                onClick={() => setSelected(a.id)}
                className={`w-full px-1 py-1.5 text-left hover:bg-sky-50 dark:hover:bg-slate-800 ${selected === a.id ? 'bg-sky-100 dark:bg-slate-700' : ''}`}
              >
                <SeverityChip severity={a.severity} /> <span className="font-medium">{a.title}</span>
                <span className="block text-xs text-slate-500">
                  {a.status}
                  {a.stale ? ' · stale' : ''} · {a.host ?? '-'} · {formatUtc(a.last_seen)} · {a.event_count} events
                </span>
              </button>
            </li>
          ))}
        </ul>
        {list.data && list.data.items.length === 0 && <p className="text-sm text-slate-500">No alerts.</p>}
      </Panel>
      <Panel title="Alert detail">
        {selected ? <AlertDetailPane alertId={selected} /> : <p className="text-sm text-slate-500">Select an alert.</p>}
      </Panel>
    </div>
  )
}
