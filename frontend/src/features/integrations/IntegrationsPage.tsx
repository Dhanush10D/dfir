import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'

import { api } from '@/api/endpoints'
import type { Integration, IntegrationType, NotificationRecipients, NotificationRule } from '@/api/types'
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

const labelClass = 'flex flex-col gap-1 text-sm'
const fieldClass = `${inputClass} w-full`
const subPanelClass = 'rounded-md border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950/40'
const checkClass = 'inline-flex items-center gap-2'

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className={labelClass}>
      <span className="font-medium">{label}</span>
      {children}
    </label>
  )
}

function SecretInput({ label, value, onChange }: { label: string; value: string; onChange: (v: string) => void }) {
  return (
    <Field label={label}>
      <input
        type="password"
        autoComplete="new-password"
        className={fieldClass}
        value={value}
        maxLength={4096}
        onChange={(e) => onChange(e.target.value)}
      />
    </Field>
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
    <form onSubmit={submit} aria-label="New integration" className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Type">
          <select className={fieldClass} value={type} onChange={(e) => setType(e.target.value as IntegrationType)}>
            {TYPES.map((t) => (
              <option key={t.id} value={t.id}>
                {t.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Name">
          <input className={fieldClass} value={name} maxLength={64} required onChange={(e) => setName(e.target.value)} />
        </Field>
        {(type === 'webhook_out' || type === 'misp') && (
          <Field label="URL (https)">
            <input className={fieldClass} value={url} maxLength={2048} required onChange={(e) => setUrl(e.target.value)} />
          </Field>
        )}
        {type === 'misp' && (
          <Field label="Highest TLP to send">
            <select className={fieldClass} value={maxTlp} onChange={(e) => setMaxTlp(e.target.value)}>
              {['clear', 'green', 'amber', 'amber+strict'].map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </Field>
        )}
        {type === 'webhook_in' && (
          <Field label="Case id (alerts go to this case)">
            <input className={`${fieldClass} font-mono`} value={caseId} maxLength={36} required onChange={(e) => setCaseId(e.target.value)} />
          </Field>
        )}
        {type === 'email' && (
          <>
            <Field label="SMTP host">
              <input className={fieldClass} value={host} maxLength={253} required onChange={(e) => setHost(e.target.value)} />
            </Field>
            <Field label="Sender">
              <input className={fieldClass} value={sender} maxLength={320} required onChange={(e) => setSender(e.target.value)} />
            </Field>
            <Field label="Recipients (comma separated)">
              <input className={fieldClass} value={recipients} required onChange={(e) => setRecipients(e.target.value)} />
            </Field>
          </>
        )}
      </div>
      {CHANNELS.has(type) && (
        <fieldset className="text-sm">
          <legend className="mb-2 font-medium">Events</legend>
          <div className="grid gap-x-4 gap-y-2 sm:grid-cols-2 lg:grid-cols-4">
            {EVENTS.map((ev) => (
              <label key={ev} className={`${checkClass} font-mono text-xs`}>
                <input
                  type="checkbox"
                  checked={events.includes(ev)}
                  onChange={(e) => setEvents(e.target.checked ? [...events, ev] : events.filter((x) => x !== ev))}
                />
                {ev}
              </label>
            ))}
          </div>
        </fieldset>
      )}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {CHANNELS.has(type) && (
          <Field label="Minimum severity">
            <select className={fieldClass} value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s || 'any'}
                </option>
              ))}
            </select>
          </Field>
        )}
        <SecretInput label={info.secretLabel} value={secret} onChange={setSecret} />
      </div>
      {CHANNELS.has(type) && (
        <label className={`${checkClass} text-sm`}>
          <input type="checkbox" checked={details} onChange={(e) => setDetails(e.target.checked)} />
          Include evidence-derived details (alert title, host)
        </label>
      )}
      <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-800">
        <Button type="submit" variant="primary" disabled={create.isPending || (!secretsAvailable && secret !== '')}>
          Create integration
        </Button>
        <span className="text-xs text-slate-500">New integrations start disabled. Enable one below once it is set up.</span>
      </div>
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
    <li className="space-y-3 rounded-md border border-slate-200 p-4 text-sm dark:border-slate-800">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-semibold">{item.name}</span>
        <span className="text-slate-500">{info.label}</span>
        <span
          className={`ml-auto rounded px-2 py-0.5 text-xs font-medium ${
            item.enabled
              ? 'bg-emerald-100 text-emerald-900 dark:bg-emerald-900/40 dark:text-emerald-200'
              : 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200'
          }`}
        >
          {item.enabled ? 'enabled' : 'disabled'}
        </span>
      </div>
      <p className="text-xs text-slate-600 dark:text-slate-400">
        Secret: {item.has_secret ? `set (fingerprint ${item.secret_fingerprint ?? '-'}, key ${item.secret_key_id ?? '-'})` : 'not set'}
        {item.case_id && ` · case ${item.case_id}`}
        {item.last_status && ` · last status: ${item.last_status} at ${formatUtc(item.last_status_at)}`}
      </p>
      <pre className="overflow-x-auto rounded bg-slate-100 p-2 font-mono text-xs whitespace-pre-wrap break-all dark:bg-slate-950">
        {JSON.stringify(item.config, null, 2)}
      </pre>
      {item.type === 'webhook_in' && (
        <p className="break-all text-xs">
          Ingest endpoint (POST, signed with X-Timestamp and X-Signature):{' '}
          <span className="font-mono">/api/v1/ingest/webhook/{item.id}</span>
        </p>
      )}
      <div className="flex flex-wrap items-end gap-3">
        <div className="w-full sm:w-72">
          <SecretInput label={`New ${info.secretLabel.toLowerCase()}`} value={secret} onChange={setSecret} />
        </div>
        <Button disabled={saveSecret.isPending || !secret} onClick={() => saveSecret.mutate()}>
          Replace secret
        </Button>
        <div className="flex flex-wrap gap-2 sm:ml-auto">
          <Button disabled={toggle.isPending} onClick={() => toggle.mutate()}>
            {item.enabled ? 'Disable' : 'Enable'}
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
      </div>
      {test.data && <p role="status" className="text-xs">Test event queued; see the delivery log.</p>}
      <ErrorMessage error={toggle.error ?? saveSecret.error ?? test.error} />
      {showLog && <Deliveries id={item.id} />}
    </li>
  )
}

const RECIPIENTS: { id: NotificationRecipients; label: string }[] = [
  { id: 'admins', label: 'administrators' },
  { id: 'case_lead', label: 'case lead' },
  { id: 'case_members', label: 'case members' },
  { id: 'case_approvers', label: 'case approvers' },
]

/** In-app notification rules (who gets a notification for which event). No templates: the
 * server builds every message from fixed text and identifiers. */
function NotificationRules() {
  const client = useQueryClient()
  const q = useQuery({ queryKey: ['notification-rules'], queryFn: ({ signal }) => api.notificationRules(signal) })
  const [draft, setDraft] = useState<NotificationRule[] | null>(null)
  const [event, setEvent] = useState(EVENTS[0]!)
  const [minSeverity, setMinSeverity] = useState('')
  const [recipients, setRecipients] = useState<NotificationRecipients[]>([])
  const save = useMutation({
    mutationFn: (rules: NotificationRule[]) => api.setNotificationRules(rules),
    onSuccess: (data) => {
      setDraft(null)
      client.setQueryData(['notification-rules'], data)
    },
  })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const rules = draft ?? q.data.rules
  const change = (next: NotificationRule[]) => setDraft(next)
  function add(e: FormEvent) {
    e.preventDefault()
    if (recipients.length === 0) return
    change([...rules, { event, min_severity: minSeverity || null, recipients, enabled: true }])
    setRecipients([])
  }
  const recipientLabel = (x: NotificationRecipients) => RECIPIENTS.find((c) => c.id === x)?.label ?? x
  return (
    <div className="space-y-4">
      {rules.length === 0 ? (
        <p className="text-sm text-slate-500">No rules: nobody gets in-app notifications.</p>
      ) : (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Notification rules</caption>
          <thead className="text-xs text-slate-500 uppercase">
            <tr>
              <th scope="col" className="py-2">Event</th>
              <th scope="col">Minimum severity</th>
              <th scope="col">Recipients</th>
              <th scope="col">Enabled</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r, i) => (
              <tr key={`${r.event}-${i}`} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-2 font-mono text-xs">{r.event}</td>
                <td>{r.min_severity ? `${r.min_severity}+` : 'any'}</td>
                <td>{r.recipients.map(recipientLabel).join(', ')}</td>
                <td>
                  <input
                    type="checkbox"
                    aria-label={`Rule ${i + 1} enabled`}
                    checked={r.enabled}
                    onChange={(e) => change(rules.map((x, j) => (j === i ? { ...x, enabled: e.target.checked } : x)))}
                  />
                </td>
                <td className="text-right">
                  <Button variant="ghost" onClick={() => change(rules.filter((_, j) => j !== i))}>
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={add} aria-label="New notification rule" className={`${subPanelClass} space-y-4`}>
        <h3 className="text-sm font-semibold">Add a rule</h3>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Event">
            <select className={fieldClass} value={event} onChange={(e) => setEvent(e.target.value)}>
              {EVENTS.map((ev) => (
                <option key={ev}>{ev}</option>
              ))}
            </select>
          </Field>
          <Field label="Rule minimum severity">
            <select className={fieldClass} value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s || 'any'}
                </option>
              ))}
            </select>
          </Field>
        </div>
        <fieldset className="text-sm">
          <legend className="mb-2 font-medium">Recipients</legend>
          <div className="flex flex-wrap gap-x-6 gap-y-2">
            {RECIPIENTS.map((c) => (
              <label key={c.id} className={checkClass}>
                <input
                  type="checkbox"
                  checked={recipients.includes(c.id)}
                  onChange={(e) =>
                    setRecipients(e.target.checked ? [...recipients, c.id] : recipients.filter((x) => x !== c.id))
                  }
                />
                {c.label}
              </label>
            ))}
          </div>
        </fieldset>
        <Button type="submit" disabled={recipients.length === 0}>
          Add rule
        </Button>
      </form>
      <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-800">
        <Button variant="primary" disabled={draft === null || save.isPending} onClick={() => save.mutate(rules)}>
          Save rules
        </Button>
        {draft !== null ? (
          <>
            <Button variant="ghost" onClick={() => setDraft(null)}>
              Discard changes
            </Button>
            <span className="text-xs text-amber-700 dark:text-amber-300">Unsaved changes</span>
          </>
        ) : (
          <span className="text-xs text-slate-500">Changes apply only after you save.</span>
        )}
      </div>
      <ErrorMessage error={save.error} />
    </div>
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
    <div className="space-y-4">
      <Panel title="Integrations">
        <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
          Credentials are stored encrypted and are never shown again. Outbound requests go to public https addresses
          only, unless the server&apos;s allowlist says otherwise.
        </p>
        {q.isPending && <Loading />}
        <ErrorMessage error={q.error} />
        {q.data && (
          <>
            <div className={subPanelClass}>
              <h3 className="mb-4 text-sm font-semibold">Add an integration</h3>
              <CreateForm secretsAvailable={q.data.secrets_available} />
            </div>
            <h3 className="mt-6 mb-3 text-sm font-semibold">Configured integrations</h3>
            {q.data.items.length === 0 ? (
              <p className="text-sm text-slate-500">None yet.</p>
            ) : (
              <ul className="space-y-3">
                {q.data.items.map((item) => (
                  <Row key={item.id} item={item} />
                ))}
              </ul>
            )}
          </>
        )}
      </Panel>
      <Panel title="In-app notification rules">
        <NotificationRules />
      </Panel>
    </div>
  )
}
