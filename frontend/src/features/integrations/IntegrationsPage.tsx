import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { Integration, IntegrationType } from '@/api/types'
import { useAuth } from '@/auth/AuthContext'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { formatUtc, shortHash } from '@/lib/format'

/**
 * Integration settings (guide 19.3), admin only.
 *
 * Secrets are write-only: a password input sends a new value, the API never returns one, and the
 * page shows only "set" plus a keyed fingerprint. Everything from the server (names, URLs, status
 * text, delivery errors) renders as plain text; nothing here becomes a link or HTML.
 */

const TYPES: { id: IntegrationType; label: string; secret: string; secretLabel: string }[] = [
  { id: 'webhook_out', label: 'Outbound webhook (signed)', secret: 'signing_secret', secretLabel: 'Signing secret (32+ characters)' },
  { id: 'webhook_in', label: 'SIEM/EDR ingest source', secret: 'signing_secret', secretLabel: 'Signing secret (32+ characters)' },
  { id: 'slack', label: 'Slack notifications', secret: 'webhook_url', secretLabel: 'Incoming webhook URL' },
  { id: 'teams', label: 'Teams notifications', secret: 'webhook_url', secretLabel: 'Incoming webhook URL' },
  { id: 'email', label: 'E-mail notifications', secret: 'password', secretLabel: 'SMTP password (optional)' },
  { id: 'virustotal', label: 'VirusTotal enrichment', secret: 'api_key', secretLabel: 'API key' },
  { id: 'misp', label: 'MISP enrichment', secret: 'api_key', secretLabel: 'API key' },
]
const CHANNELS = new Set<IntegrationType>(['webhook_out', 'slack', 'teams', 'email'])
const EVENTS = [
  'alert.created',
  'case.status_changed',
  'report.signed',
  'evidence.verification_failed',
  'playbook.run_started',
  'playbook.approval_requested',
  'playbook.notice',
]
const SEVERITIES = ['', 'info', 'low', 'medium', 'high', 'critical']

function typeInfo(type: IntegrationType) {
  return TYPES.find((t) => t.id === type) ?? TYPES[0]!
}

function SecretInput({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <label className="text-sm">
      <span className="mb-1 block font-medium">{label}</span>
      <input
        type="password"
        autoComplete="new-password"
        className={`${inputClass} w-72`}
        value={value}
        maxLength={4096}
        onChange={(e) => onChange(e.target.value)}
      />
    </label>
  )
}

function CreateForm({ secretsAvailable }: { secretsAvailable: boolean }) {
  const client = useQueryClient()
  const [type, setType] = useState<IntegrationType>('webhook_out')
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [events, setEvents] = useState<string[]>([])
  const [minSeverity, setMinSeverity] = useState('')
  const [details, setDetails] = useState(false)
  const [caseId, setCaseId] = useState('')
  const [host, setHost] = useState('')
  const [sender, setSender] = useState('')
  const [recipients, setRecipients] = useState('')
  const [maxTlp, setMaxTlp] = useState('green')
  const [secret, setSecret] = useState('')
  const info = typeInfo(type)

  function config(): Record<string, unknown> {
    const out: Record<string, unknown> = {}
    if (CHANNELS.has(type)) {
      out.events = events
      out.include_details = details
      if (minSeverity) out.min_severity = minSeverity
    }
    if (type === 'webhook_out') out.url = url.trim()
    if (type === 'misp') {
      out.url = url.trim()
      out.max_tlp = maxTlp
    }
    if (type === 'email') {
      out.host = host.trim()
      out.sender = sender.trim()
      out.recipients = recipients
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean)
    }
    return out
  }

  const create = useMutation({
    mutationFn: () =>
      api.createIntegration({
        type,
        name: name.trim(),
        config: config(),
        ...(secret ? { secret: { [info.secret]: secret } } : {}),
        enabled: false,
        ...(type === 'webhook_in' && caseId.trim() ? { case_id: caseId.trim() } : {}),
      }),
    onSuccess: () => {
      setSecret('') // never keep a secret in the page after it was sent
      setName('')
      void client.invalidateQueries({ queryKey: ['integrations'] })
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate()
  }
  return (
    <form onSubmit={submit} aria-label="New integration" className="flex flex-wrap items-end gap-2">
      <label className="text-sm">
        <span className="mb-1 block font-medium">Type</span>
        <select className={inputClass} value={type} onChange={(e) => setType(e.target.value as IntegrationType)}>
          {TYPES.map((t) => (
            <option key={t.id} value={t.id}>
              {t.label}
            </option>
          ))}
        </select>
      </label>
      <label className="text-sm">
        <span className="mb-1 block font-medium">Name</span>
        <input className={inputClass} value={name} maxLength={64} required onChange={(e) => setName(e.target.value)} />
      </label>
      {(type === 'webhook_out' || type === 'misp') && (
        <label className="text-sm">
          <span className="mb-1 block font-medium">URL (https)</span>
          <input className={`${inputClass} w-80`} value={url} maxLength={2048} required onChange={(e) => setUrl(e.target.value)} />
        </label>
      )}
      {type === 'misp' && (
        <label className="text-sm">
          <span className="mb-1 block font-medium">Highest TLP to send</span>
          <select className={inputClass} value={maxTlp} onChange={(e) => setMaxTlp(e.target.value)}>
            {['clear', 'green', 'amber', 'amber+strict'].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
      )}
      {type === 'webhook_in' && (
        <label className="text-sm">
          <span className="mb-1 block font-medium">Case id (alerts go to this case)</span>
          <input className={`${inputClass} w-80 font-mono`} value={caseId} maxLength={36} required onChange={(e) => setCaseId(e.target.value)} />
        </label>
      )}
      {type === 'email' && (
        <>
          <label className="text-sm">
            <span className="mb-1 block font-medium">SMTP host</span>
            <input className={inputClass} value={host} maxLength={253} required onChange={(e) => setHost(e.target.value)} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium">Sender</span>
            <input className={inputClass} value={sender} maxLength={320} required onChange={(e) => setSender(e.target.value)} />
          </label>
          <label className="text-sm">
            <span className="mb-1 block font-medium">Recipients (comma separated)</span>
            <input className={`${inputClass} w-72`} value={recipients} required onChange={(e) => setRecipients(e.target.value)} />
          </label>
        </>
      )}
      {CHANNELS.has(type) && (
        <>
          <fieldset className="text-sm">
            <legend className="mb-1 font-medium">Events</legend>
            {EVENTS.map((ev) => (
              <label key={ev} className="mr-2 inline-flex items-center gap-1">
                <input
                  type="checkbox"
                  checked={events.includes(ev)}
                  onChange={(e) => setEvents(e.target.checked ? [...events, ev] : events.filter((x) => x !== ev))}
                />
                {ev}
              </label>
            ))}
          </fieldset>
          <label className="text-sm">
            <span className="mb-1 block font-medium">Minimum severity</span>
            <select className={inputClass} value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s || 'any'}
                </option>
              ))}
            </select>
          </label>
          <label className="inline-flex items-center gap-1 text-sm">
            <input type="checkbox" checked={details} onChange={(e) => setDetails(e.target.checked)} />
            Include evidence-derived details (alert title, host)
          </label>
        </>
      )}
      <SecretInput label={info.secretLabel} value={secret} onChange={setSecret} />
      <Button type="submit" variant="primary" disabled={create.isPending || (!secretsAvailable && secret !== '')}>
        Create (disabled)
      </Button>
      {!secretsAvailable && (
        <p className="text-sm text-amber-800 dark:text-amber-300">
          No key-encryption key is configured on the server (INTEGRATION_KEK): secrets cannot be saved.
        </p>
      )}
      <ErrorMessage error={create.error} />
    </form>
  )
}

function Deliveries({ id }: { id: string }) {
  const q = useQuery({ queryKey: ['deliveries', id], queryFn: ({ signal }) => api.deliveries(id, signal) })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const { outbound, inbound } = q.data
  if (outbound.length === 0 && inbound.length === 0) return <p className="text-xs text-slate-500">No deliveries yet.</p>
  return (
    <ul className="font-mono text-xs">
      {outbound.map((d) => (
        <li key={d.id}>
          {formatUtc(d.created_at)} {d.event_type}: {d.status}, attempt {d.attempts}/{d.max_attempts}
          {d.response_status !== null && `, HTTP ${d.response_status}`}
          {d.last_error && `, ${d.last_error}`}
          {d.next_attempt_at && `, next try ${formatUtc(d.next_attempt_at)}`}
        </li>
      ))}
      {inbound.map((d) => (
        <li key={d.id}>
          {formatUtc(d.received_at)} received {d.items} items: {d.created} created, {d.updated} updated, {d.errors}{' '}
          errors (body sha256 {shortHash(d.body_sha256)})
        </li>
      ))}
    </ul>
  )
}

function Row({ item }: { item: Integration }) {
  const client = useQueryClient()
  const [secret, setSecret] = useState('')
  const [showLog, setShowLog] = useState(false)
  const info = typeInfo(item.type)
  const refresh = () => void client.invalidateQueries({ queryKey: ['integrations'] })
  const toggle = useMutation({
    mutationFn: () => api.updateIntegration(item.id, { enabled: !item.enabled }),
    onSuccess: refresh,
  })
  const saveSecret = useMutation({
    mutationFn: () => api.updateIntegration(item.id, { secret: { [info.secret]: secret } }),
    onSuccess: () => {
      setSecret('')
      refresh()
    },
  })
  const test = useMutation({
    mutationFn: () => api.testIntegration(item.id),
    onSuccess: () => {
      setShowLog(true)
      void client.invalidateQueries({ queryKey: ['deliveries', item.id] })
    },
  })
  return (
    <li className="border-t border-slate-200 py-2 text-sm dark:border-slate-800">
      <p>
        <span className="font-semibold">{item.name}</span> <span className="text-slate-500">({info.label})</span>{' '}
        <span className="rounded bg-slate-200 px-1.5 py-0.5 text-xs dark:bg-slate-700">
          {item.enabled ? 'enabled' : 'disabled'}
        </span>
      </p>
      <p className="text-xs text-slate-600 dark:text-slate-400">
        Secret: {item.has_secret ? `set (fingerprint ${item.secret_fingerprint ?? '-'}, key ${item.secret_key_id ?? '-'})` : 'not set'}
        {item.case_id && ` · case ${item.case_id}`}
        {item.last_status && ` · last status: ${item.last_status} at ${formatUtc(item.last_status_at)}`}
      </p>
      <p className="break-all font-mono text-xs">{JSON.stringify(item.config)}</p>
      <div className="mt-1 flex flex-wrap items-end gap-2">
        <Button disabled={toggle.isPending} onClick={() => toggle.mutate()}>
          {item.enabled ? 'Disable' : 'Enable'}
        </Button>
        <SecretInput label={`New ${info.secretLabel.toLowerCase()}`} value={secret} onChange={setSecret} />
        <Button disabled={saveSecret.isPending || !secret} onClick={() => saveSecret.mutate()}>
          Replace secret
        </Button>
        {CHANNELS.has(item.type) && (
          <Button disabled={test.isPending || !item.enabled} onClick={() => test.mutate()}>
            Send test
          </Button>
        )}
        <Button variant="ghost" aria-expanded={showLog} onClick={() => setShowLog(!showLog)}>
          Delivery log
        </Button>
      </div>
      {test.data && <p role="status" className="text-xs">Test event queued; see the delivery log.</p>}
      <ErrorMessage error={toggle.error ?? saveSecret.error ?? test.error} />
      {showLog && <Deliveries id={item.id} />}
    </li>
  )
}

export function IntegrationsPage() {
  const { can } = useAuth()
  const allowed = can('users:manage')
  const q = useQuery({
    queryKey: ['integrations'],
    queryFn: ({ signal }) => api.integrations(signal),
    enabled: allowed,
  })
  if (!allowed) return <p>Integrations are managed by administrators.</p>
  return (
    <div className="space-y-3">
      <Panel title="Integrations">
        <p className="mb-2 text-sm text-slate-600 dark:text-slate-400">
          Credentials are stored encrypted and are never shown again. Outbound requests go to public https addresses
          only, unless the server&apos;s allowlist says otherwise.
        </p>
        {q.isPending && <Loading />}
        <ErrorMessage error={q.error} />
        {q.data && <CreateForm secretsAvailable={q.data.secrets_available} />}
        <ul className="mt-3">
          {(q.data?.items ?? []).map((item) => (
            <Row key={item.id} item={item} />
          ))}
        </ul>
      </Panel>
    </div>
  )
}
