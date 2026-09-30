import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'

import { api } from '@/api/endpoints'
import type { AiResult } from '@/api/types'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

import { AiResultCard, type AiView } from './AiResultCard'

/**
 * AI analyst tab (guide 17.2 "AI analyst"): chat over case evidence, plain-language search,
 * attack narrative and static script explanation, plus the case's AI history. Every answer is a
 * suggestion: it is shown with provenance and must be accepted by a person.
 */

function Ask({
  label,
  placeholder,
  button,
  multiline = false,
  run,
}: {
  label: string
  placeholder: string
  button: string
  multiline?: boolean
  run: (text: string) => Promise<AiResult>
}) {
  const [text, setText] = useState('')
  const call = useMutation({ mutationFn: () => run(text.trim()) })
  function submit(e: FormEvent) {
    e.preventDefault()
    if (text.trim()) call.mutate()
  }
  return (
    <div className="space-y-2">
      <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label={label}>
        <label className="flex-1 text-sm">
          <span className="mb-1 block font-medium">{label}</span>
          {multiline ? (
            <textarea
              className={`${inputClass} h-28 w-full font-mono`}
              value={text}
              maxLength={100000}
              placeholder={placeholder}
              onChange={(e) => setText(e.target.value)}
            />
          ) : (
            <input
              className={`${inputClass} w-full`}
              value={text}
              maxLength={2000}
              placeholder={placeholder}
              onChange={(e) => setText(e.target.value)}
            />
          )}
        </label>
        <Button type="submit" variant="primary" disabled={call.isPending || !text.trim()}>
          {call.isPending ? 'Working…' : button}
        </Button>
      </form>
      <ErrorMessage error={call.error} />
      {call.data && <AiResultCard key={call.data.interaction.id} view={call.data} />}
      {call.data?.extras.analysis !== undefined && <ScriptAnalysis analysis={call.data.extras.analysis} />}
    </div>
  )
}

interface Analysis {
  layers: { index: number; method: string; text: string }[]
  indicators: { type: string; value: string; layer: number }[]
  techniques: { technique: string; reason: string }[]
}

function ScriptAnalysis({ analysis }: { analysis: unknown }) {
  const a = analysis as Analysis
  return (
    <details className="text-sm">
      <summary className="cursor-pointer font-medium">Deterministic decoding (never executed)</summary>
      <ol className="mt-1 list-decimal space-y-1 pl-5">
        {a.layers.map((l) => (
          <li key={l.index}>
            <span className="text-xs text-slate-500">{l.method}</span>
            <pre className="max-h-32 overflow-auto rounded bg-slate-100 p-1 text-xs whitespace-pre-wrap dark:bg-slate-800">
              {l.text}
            </pre>
          </li>
        ))}
      </ol>
      {a.indicators.length > 0 && (
        <ul className="mt-1 list-disc pl-5">
          {a.indicators.map((i) => (
            <li key={`${i.type}:${i.value}`}>
              {i.type}: <code className="font-mono break-all">{i.value}</code>
            </li>
          ))}
        </ul>
      )}
      {a.techniques.length > 0 && (
        <p className="mt-1">ATT&amp;CK hints: {a.techniques.map((t) => `${t.technique} (${t.reason})`).join('; ')}</p>
      )}
    </details>
  )
}

function Narrative() {
  const { caseId } = useCase()
  const [host, setHost] = useState('')
  const call = useMutation({ mutationFn: () => api.aiNarrative(caseId, host ? { host } : {}) })
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Host (optional)</span>
          <input className={inputClass} value={host} maxLength={255} onChange={(e) => setHost(e.target.value)} />
        </label>
        <Button variant="primary" disabled={call.isPending} onClick={() => call.mutate()}>
          {call.isPending ? 'Working…' : 'Build narrative'}
        </Button>
      </div>
      <ErrorMessage error={call.error} />
      {call.data && <AiResultCard key={call.data.interaction.id} view={call.data} />}
    </div>
  )
}

function History() {
  const { caseId } = useCase()
  const list = useQuery({
    queryKey: ['ai-interactions', caseId],
    queryFn: ({ signal }) => api.aiInteractions(caseId, signal),
  })
  const [openId, setOpenId] = useState<string | null>(null)
  const detail = useQuery({
    queryKey: ['ai-interaction', openId],
    queryFn: ({ signal }) => api.aiInteraction(openId as string, signal),
    enabled: openId !== null,
  })
  if (list.isPending) return <Loading />
  if (list.error) return <ErrorMessage error={list.error} />
  const view: AiView | null = detail.data
    ? {
        interaction: detail.data,
        output: detail.data.output,
        citations: Object.fromEntries(detail.data.citations.map((c) => [c.short_id, c])),
        problems: detail.data.error ? [detail.data.error] : [],
      }
    : null
  return (
    <div className="space-y-2">
      <ul className="divide-y divide-slate-100 text-sm dark:divide-slate-800">
        {list.data.items.map((it) => (
          <li key={it.id}>
            <button
              type="button"
              aria-pressed={openId === it.id}
              onClick={() => setOpenId(it.id)}
              className="w-full px-1 py-1 text-left hover:bg-sky-50 dark:hover:bg-slate-800"
            >
              {formatUtc(it.created_at)} · {it.feature} · {it.status}
              {it.accepted === true ? ' · accepted' : it.accepted === false ? ' · rejected' : ''}
              {it.warnings.some((w) => w.type === 'injection_suspected') ? ' · warning' : ''}
            </button>
          </li>
        ))}
      </ul>
      {list.data.items.length === 0 && <p className="text-sm text-slate-500">No AI activity yet.</p>}
      {detail.isFetching && <Loading />}
      {view && <AiResultCard key={view.interaction.id} view={view} />}
    </div>
  )
}

function CaseSwitch() {
  const { caseId, detail, can } = useCase()
  const client = useQueryClient()
  const [enabled, setEnabled] = useState(detail.ai_enabled !== false)
  const change = useMutation({
    mutationFn: (value: boolean) => api.aiSetCase(caseId, value),
    onSuccess: (d) => {
      setEnabled(d.ai_enabled)
      void client.invalidateQueries({ queryKey: ['case', caseId] })
    },
  })
  if (!can('case:manage')) return <p className="text-xs text-slate-500">AI for this case: {enabled ? 'on' : 'off'}</p>
  return (
    <div className="flex items-center gap-2 text-sm">
      <span>AI for this case: {enabled ? 'on' : 'off'}</span>
      <Button disabled={change.isPending} onClick={() => change.mutate(!enabled)}>
        {enabled ? 'Switch off' : 'Switch on'}
      </Button>
      <ErrorMessage error={change.error} />
    </div>
  )
}

function Block({ title, children }: { title: string; children: ReactNode }) {
  return <Panel title={title}>{children}</Panel>
}

export function AiTab() {
  const { caseId, can } = useCase()
  const status = useQuery({ queryKey: ['ai-status'], queryFn: ({ signal }) => api.aiStatus(signal) })
  const s = status.data
  const usable = can('ai:use')
  return (
    <div className="space-y-3">
      <Panel title="AI analyst">
        {status.isPending && <Loading />}
        <ErrorMessage error={status.error} />
        {s && (
          <p className="text-sm">
            {s.enabled ? 'AI is on' : 'AI is switched off on this server'} · provider {s.provider}
            {s.local_only ? ' (local only)' : ''} · models {s.models.fast} / {s.models.strong} · redaction{' '}
            {s.redaction_policy}
            {s.enabled && !s.configured ? ' · provider not configured' : ''}
          </p>
        )}
        <p className="text-xs text-slate-500">
          Answers are suggestions grounded in this case's evidence. Citations are checked on the server; nothing is
          changed until a person accepts it.
        </p>
        <CaseSwitch />
      </Panel>
      {usable ? (
        <div className="grid gap-3 lg:grid-cols-2">
          <Block title="Ask the case (chat)">
            <Ask
              label="Question"
              placeholder="What did the attacker do on ws-042?"
              button="Ask"
              run={(q) => api.aiChat(caseId, q)}
            />
          </Block>
          <Block title="Search in plain language">
            <Ask
              label="Describe the events"
              placeholder="failed ssh logins from 203.0.113.50"
              button="Translate"
              run={(q) => api.aiNlq(caseId, q)}
            />
          </Block>
          <Block title="Attack narrative">
            <Narrative />
          </Block>
          <Block title="Explain a script or command">
            <Ask
              label="Script or command line"
              placeholder="powershell -enc ..."
              button="Explain"
              multiline
              run={(t) => api.aiScript(caseId, t)}
            />
          </Block>
        </div>
      ) : (
        <p className="text-sm text-slate-500">Your role on this case cannot use AI features.</p>
      )}
      <Panel title="AI history">
        <History />
      </Panel>
    </div>
  )
}
