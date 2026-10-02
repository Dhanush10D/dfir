import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'

import { api } from '@/api/endpoints'
import type { AiCitation, AiInteraction, AiWarning } from '@/api/types'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { Button, ErrorMessage, inputClass, Loading } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

/**
 * One AI answer with everything an analyst needs to judge it (guide 13.12): an "AI-generated"
 * badge, model / prompt version / time, validation status, warnings (instruction-like evidence,
 * unsupported claims), every claim with clickable citations, accept / reject (once, audited),
 * feedback, and the prompt as it was sent (redacted). All model text is rendered as plain text.
 */

const BLOCKING = new Set(['injection_suspected', 'unsupported_claim'])

export interface AiView {
  interaction: AiInteraction
  output: Record<string, unknown>
  citations: Record<string, AiCitation>
  problems: string[]
}

type Item = Record<string, unknown>

function asText(v: unknown): string {
  return typeof v === 'string' ? v : v === null || v === undefined ? '' : JSON.stringify(v)
}

function items(v: unknown): Item[] {
  return Array.isArray(v) ? v.filter((x): x is Item => typeof x === 'object' && x !== null) : []
}

function strings(v: unknown): string[] {
  return Array.isArray(v) ? v.map(asText) : []
}

export function CitationChip({ sid, citation }: { sid: string; citation?: AiCitation }) {
  const { caseId } = useCase()
  const [open, setOpen] = useState(false)
  return (
    <span className="relative inline-block">
      <button
        type="button"
        aria-expanded={open}
        aria-label={`Citation ${sid}`}
        onClick={() => setOpen((o) => !o)}
        className="mx-0.5 rounded bg-sky-100 px-1 font-mono text-xs text-sky-900 hover:bg-sky-200 dark:bg-sky-900 dark:text-sky-100"
      >
        {sid}
      </button>
      {open && (
        <span
          role="note"
          className="absolute z-10 mt-1 block w-80 rounded border border-slate-300 bg-white p-2 text-xs shadow dark:border-slate-600 dark:bg-slate-800"
        >
          {citation ? (
            <>
              <span className="block font-mono break-all">{citation.summary}</span>
              {citation.kind === 'event' && citation.id && (
                <Link
                  className="text-sky-700 hover:underline dark:text-sky-400"
                  to={caseHref(caseId, 'timeline', { q: `id:${citation.id}` })}
                >
                  Open event in timeline
                </Link>
              )}
              {citation.kind === 'alert' && (
                <Link className="text-sky-700 hover:underline dark:text-sky-400" to={caseHref(caseId, 'alerts')}>
                  Open alerts
                </Link>
              )}
            </>
          ) : (
            <span>Not a record of this answer.</span>
          )}
        </span>
      )}
    </span>
  )
}

function Cites({ ids, citations }: { ids: unknown; citations: Record<string, AiCitation> }) {
  const list = strings(ids)
  if (!list.length) return null
  return (
    <span aria-label="citations">
      {list.map((sid) => (
        <CitationChip key={sid} sid={sid} citation={citations[sid]} />
      ))}
    </span>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h4 className="text-xs font-semibold uppercase text-slate-500">{title}</h4>
      {children}
    </div>
  )
}

function ListOf({
  title,
  rows,
  citations,
  render,
}: {
  title: string
  rows: Item[]
  citations: Record<string, AiCitation>
  render: (row: Item) => ReactNode
}) {
  if (!rows.length) return null
  return (
    <Section title={title}>
      <ul className="list-disc space-y-1 pl-5 text-sm">
        {rows.map((row, i) => (
          <li key={i}>
            {render(row)} <Cites ids={row.cites} citations={citations} />
          </li>
        ))}
      </ul>
    </Section>
  )
}

export function AiOutput({ output, citations }: { output: Record<string, unknown>; citations: Record<string, AiCitation> }) {
  const { caseId } = useCase()
  const o = output
  return (
    <div className="space-y-2">
      {'query' in o && (
        <Section title="Query">
          {o.query ? (
            <p className="text-sm">
              <code className="rounded bg-slate-100 px-1 font-mono dark:bg-slate-800">{asText(o.query)}</code>{' '}
              <Link
                className="text-sky-700 hover:underline dark:text-sky-400"
                to={caseHref(caseId, 'timeline', { q: asText(o.query) })}
              >
                Run in timeline
              </Link>
            </p>
          ) : (
            <p className="text-sm">No query could be built.</p>
          )}
        </Section>
      )}
      {(['summary', 'answer', 'explanation', 'text'] as const).map((k) =>
        typeof o[k] === 'string' && o[k] ? (
          <p key={k} className="text-sm whitespace-pre-wrap">
            {asText(o[k])}
          </p>
        ) : null,
      )}
      <p className="flex flex-wrap gap-3 text-sm">
        {'assessment' in o && (
          <span>
            Assessment: <strong>{asText(o.assessment)}</strong>
            {typeof o.confidence === 'number' && ` (confidence ${o.confidence.toFixed(2)})`}
          </span>
        )}
        {'risk' in o && (
          <span>
            Risk: <strong>{asText(o.risk)}</strong>
          </span>
        )}
        {'status' in o && (
          <span>
            Answer status: <strong>{asText(o.status)}</strong>
          </span>
        )}
      </p>
      <ListOf title="Key facts" rows={items(o.key_facts)} citations={citations} render={(r) => asText(r.statement)} />
      <ListOf title="Claims" rows={items(o.claims)} citations={citations} render={(r) => asText(r.statement)} />
      <ListOf
        title="Timeline"
        rows={items(o.timeline)}
        citations={citations}
        render={(r) => (
          <>
            <span className="font-mono text-xs">{formatUtc(asText(r.ts))}</span> [{asText(r.stage)}] {asText(r.statement)}
          </>
        )}
      />
      <ListOf title="Behaviors" rows={items(o.behaviors)} citations={citations} render={(r) => asText(r.description)} />
      <ListOf
        title="Indicators"
        rows={items(o.indicators)}
        citations={citations}
        render={(r) => (
          <>
            {asText(r.type)}: <code className="font-mono break-all">{asText(r.value)}</code>
          </>
        )}
      />
      <ListOf
        title="Next steps"
        rows={items(o.next_steps)}
        citations={citations}
        render={(r) => `${asText(r.action)} - ${asText(r.why)}`}
      />
      <ListOf
        title="ATT&CK candidates"
        rows={items(o.attack_candidates)}
        citations={citations}
        render={(r) => `${asText(r.technique)}: ${asText(r.rationale)}`}
      />
      {strings(o.assumptions).length > 0 && (
        <Section title="Assumptions">
          <ul className="list-disc pl-5 text-sm">
            {strings(o.assumptions).map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </Section>
      )}
      {strings(o.gaps).length > 0 && (
        <Section title="Gaps">
          <ul className="list-disc pl-5 text-sm">
            {strings(o.gaps).map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </Section>
      )}
      {typeof o.limitations === 'string' && o.limitations && (
        <p className="text-xs text-slate-500">Limitations: {o.limitations}</p>
      )}
    </div>
  )
}

function warningText(w: AiWarning): string {
  if (w.type === 'injection_suspected')
    return `Record ${w.record ?? '?'} contains instruction-like text (${(w.flags ?? []).join(', ')}). Treat the answer with care.`
  if (w.type === 'unsupported_claim')
    return `Some values in the answer do not appear in the cited records: ${(w.items ?? [])
      .flatMap((i) => i.tokens)
      .slice(0, 5)
      .join(', ')}`
  if (w.type === 'retried') return 'The first reply failed validation and was retried.'
  if (w.type === 'index_truncated') return `Only the first ${w.limit ?? '?'} events are indexed for chat.`
  return w.type
}

function PromptView({ id }: { id: string }) {
  const detail = useQuery({ queryKey: ['ai-interaction', id], queryFn: ({ signal }) => api.aiInteraction(id, signal) })
  if (detail.isPending) return <Loading />
  if (detail.error) return <ErrorMessage error={detail.error} />
  const d = detail.data
  return (
    <div className="space-y-1 text-xs">
      <p>
        Redaction: {d.redaction_policy ?? 'none'}{' '}
        {Object.entries(d.redaction_counts)
          .map(([k, v]) => `${k}×${v}`)
          .join(', ')}
      </p>
      <p className="font-mono break-all">input sha256 {d.input_sha256} · prompt sha256 {d.prompt_sha256}</p>
      <pre className="max-h-64 overflow-auto rounded bg-slate-100 p-2 whitespace-pre-wrap dark:bg-slate-800">
        {d.prompt_text ?? '(nothing sent)'}
      </pre>
    </div>
  )
}

function Review({ it }: { it: AiInteraction }) {
  const { can } = useCase()
  const client = useQueryClient()
  const [ack, setAck] = useState(false)
  const [note, setNote] = useState('')
  const [current, setCurrent] = useState(it)
  const review = useMutation({
    mutationFn: (decision: 'accept' | 'reject') => api.aiReview(it.id, decision, ack, note),
    onSuccess: (d) => {
      setCurrent(d)
      // The history detail is cached per id: update it too, or reopening shows Accept/Reject again.
      client.setQueryData(['ai-interaction', it.id], d)
      void client.invalidateQueries({ queryKey: ['ai-interactions'] })
    },
  })
  const feedback = useMutation({
    mutationFn: (v: -1 | 1) => api.aiFeedback(it.id, v),
    onSuccess: (d) => {
      setCurrent(d)
      client.setQueryData(['ai-interaction', it.id], d)
    },
  })
  const blocking = current.warnings.some((w) => BLOCKING.has(w.type))
  if (current.accepted !== null)
    return (
      <p className="text-sm">
        {current.accepted ? 'Accepted' : 'Rejected'} {formatUtc(current.reviewed_at)}
        {current.review_note ? ` - ${current.review_note}` : ''}
      </p>
    )
  if (!can('ai:use') || current.status !== 'valid') return null
  return (
    <div className="space-y-2" aria-label="Review AI output">
      {blocking && (
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />I have read the warnings
        </label>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <input
          className={inputClass}
          aria-label="Review note"
          placeholder="Note (optional)"
          maxLength={2000}
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <Button variant="primary" disabled={review.isPending || (blocking && !ack)} onClick={() => review.mutate('accept')}>
          Accept
        </Button>
        <Button disabled={review.isPending} onClick={() => review.mutate('reject')}>
          Reject
        </Button>
        <Button variant="ghost" onClick={() => feedback.mutate(1)}>
          Helpful
        </Button>
        <Button variant="ghost" onClick={() => feedback.mutate(-1)}>
          Not helpful
        </Button>
        {current.feedback !== null && <span className="text-xs text-slate-500">feedback {current.feedback}</span>}
      </div>
      <ErrorMessage error={review.error ?? feedback.error} />
    </div>
  )
}

export function AiResultCard({ view }: { view: AiView }) {
  const [showPrompt, setShowPrompt] = useState(false)
  const it = view.interaction
  const valid = it.status === 'valid'
  return (
    <article
      aria-label="AI result"
      className="space-y-2 rounded border border-violet-300 bg-violet-50/50 p-3 dark:border-violet-800 dark:bg-violet-950/30"
    >
      <header className="flex flex-wrap items-center gap-2 text-xs">
        <span className="rounded bg-violet-700 px-1.5 py-0.5 font-semibold text-white">AI-generated</span>
        <span className={valid ? 'text-green-800 dark:text-green-400' : 'font-semibold text-red-700 dark:text-red-400'}>
          {valid ? 'validated (schema + citations)' : `not verified: ${it.status}`}
        </span>
        <span className="text-slate-600 dark:text-slate-400">
          {it.model_served ?? it.model} · {it.prompt_version} · {formatUtc(it.created_at)}
          {it.latency_ms !== null && ` · ${it.latency_ms} ms`}
        </span>
      </header>
      {it.warnings.length > 0 && (
        <ul role="alert" className="rounded bg-amber-100 p-2 text-sm text-amber-900 dark:bg-amber-900/40 dark:text-amber-100">
          {it.warnings.map((w, i) => (
            <li key={i}>{warningText(w)}</li>
          ))}
        </ul>
      )}
      {valid ? (
        <AiOutput output={view.output} citations={view.citations} />
      ) : (
        <div className="text-sm">
          <p className="font-medium">AI could not produce a verified answer.</p>
          <ul className="list-disc pl-5 text-xs">
            {view.problems.map((p, i) => (
              <li key={i}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      <Review key={`${it.id}-${String(it.accepted)}`} it={it} />
      <Button variant="ghost" aria-expanded={showPrompt} onClick={() => setShowPrompt((s) => !s)}>
        {showPrompt ? 'Hide what was sent' : 'Show what was sent to the model'}
      </Button>
      {showPrompt && <PromptView id={it.id} />}
    </article>
  )
}
