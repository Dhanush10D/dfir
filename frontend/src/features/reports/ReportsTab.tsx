import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api, saveBlob } from '@/api/endpoints'
import type { AiResult, ReportDetail, ReportFinding, ReportKind, ReportVerify } from '@/api/types'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { AiResultCard } from '@/features/ai/AiResultCard'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc, shortHash } from '@/lib/format'

import { parseRefs, refsToText } from './refs'

/**
 * Reports (guide 18): create from a snapshot, edit sections and evidence-cited findings, QA,
 * submit / return / approve (four eyes) / sign, verify, download, new versions, AI drafts.
 *
 * Report HTML is only ever shown inside `<iframe sandbox srcDoc>` (no scripts, opaque origin);
 * the server also sends a sandboxing CSP. All other report text renders as plain React text.
 */

const KINDS: { id: ReportKind; label: string }[] = [
  { id: 'technical', label: 'Technical incident report' },
  { id: 'executive', label: 'Executive summary' },
  { id: 'custody', label: 'Evidence and custody report' },
  { id: 'ioc', label: 'IOC package' },
]

const STATUS_TEXT: Record<string, string> = {
  draft: 'Draft',
  in_review: 'In review',
  approved: 'Approved (not signed)',
  signed: 'Signed',
}

function CreateForm({ onCreated }: { onCreated: (id: string) => void }) {
  const { caseId } = useCase()
  const client = useQueryClient()
  const [kind, setKind] = useState<ReportKind>('technical')
  const [title, setTitle] = useState('')
  const create = useMutation({
    mutationFn: () => api.createReport(caseId, kind, title),
    onSuccess: (r) => {
      setTitle('')
      void client.invalidateQueries({ queryKey: ['reports', caseId] })
      onCreated(r.id)
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    create.mutate()
  }
  return (
    <form onSubmit={submit} aria-label="New report" className="mt-3 flex flex-wrap items-end gap-2">
      <label className="text-sm">
        <span className="mb-1 block font-medium">Kind</span>
        <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value as ReportKind)}>
          {KINDS.map((k) => (
            <option key={k.id} value={k.id}>
              {k.label}
            </option>
          ))}
        </select>
      </label>
      <label className="text-sm">
        <span className="mb-1 block font-medium">Title (optional)</span>
        <input className={inputClass} value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} />
      </label>
      <Button type="submit" variant="primary" disabled={create.isPending}>
        {create.isPending ? 'Taking snapshot…' : 'Create report'}
      </Button>
      <ErrorMessage error={create.error} />
    </form>
  )
}

function Preview({ id, revision, status }: { id: string; revision: number; status: string }) {
  const q = useQuery({
    queryKey: ['report-preview', id, revision, status],
    queryFn: ({ signal }) => api.reportPreview(id, signal),
  })
  if (q.isPending) return <Loading label="Rendering…" />
  if (q.error) return <ErrorMessage error={q.error} />
  return (
    <iframe
      title="Report preview"
      sandbox=""
      referrerPolicy="no-referrer"
      srcDoc={q.data}
      className="h-[70vh] w-full rounded border border-slate-300 bg-white dark:border-slate-700"
    />
  )
}

function VerifyResultView({ result }: { result: ReportVerify }) {
  return (
    <div role="status" className="text-sm">
      <p className={`font-semibold ${result.ok ? 'text-emerald-700' : 'text-red-700'}`}>
        {result.ok ? '✓ Verified' : '✕ Verification failed'}: signature {result.signature_ok ? 'valid' : 'NOT valid'}
        {result.key_id && ` (key ${result.key_id})`}
      </p>
      <ul className="font-mono text-xs">
        {result.artifacts.map((a) => (
          <li key={a.name}>
            {a.name}: stored {a.stored_ok ? 'ok' : 'CHANGED'} · re-render {a.rerender_ok ? 'identical' : 'DIFFERENT'}
          </li>
        ))}
      </ul>
      {result.problems.length > 0 && (
        <ul className="list-disc pl-5 text-red-700">
          {result.problems.map((p, i) => (
            <li key={i}>
              {p.code}: {p.message}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function SectionAiDraft({ report, section }: { report: ReportDetail; section: string }) {
  const client = useQueryClient()
  const [result, setResult] = useState<AiResult | null>(null)
  const draft = useMutation({ mutationFn: () => api.aiDraftSection(report.id, section), onSuccess: setResult })
  const apply = useMutation({
    mutationFn: (iid: string) => api.applyAiDraft(report.id, section, iid, report.revision),
    onSuccess: (r) => {
      client.setQueryData(['report', report.id], r)
      setResult(null)
    },
  })
  return (
    <div className="space-y-2">
      <Button onClick={() => draft.mutate()} disabled={draft.isPending}>
        {draft.isPending ? 'Drafting…' : 'Draft with AI'}
      </Button>
      <ErrorMessage error={draft.error ?? apply.error} />
      {result && (
        <>
          <AiResultCard view={result} />
          <p className="text-xs text-slate-500">
            The draft enters the report only after someone accepts it above; it is then labelled as AI-drafted with
            the approver&apos;s name.
          </p>
          <Button variant="primary" onClick={() => apply.mutate(result.interaction.id)} disabled={apply.isPending}>
            Apply accepted draft to this section
          </Button>
        </>
      )}
    </div>
  )
}

function FindingEditor({
  finding,
  onChange,
  onRemove,
  disabled,
}: {
  finding: ReportFinding & { refsText: string }
  onChange: (f: ReportFinding & { refsText: string }) => void
  onRemove: () => void
  disabled: boolean
}) {
  return (
    <fieldset className="space-y-1 rounded border border-slate-200 p-2 dark:border-slate-700" disabled={disabled}>
      <legend className="px-1 text-xs text-slate-500">Finding</legend>
      <label className="block text-sm">
        <span className="font-medium">Title</span>
        <input
          className={`${inputClass} w-full`}
          value={finding.title}
          maxLength={300}
          onChange={(e) => onChange({ ...finding, title: e.target.value })}
        />
      </label>
      <label className="block text-sm">
        <span className="font-medium">Description (Markdown)</span>
        <textarea
          className={`${inputClass} w-full`}
          rows={3}
          value={finding.body}
          onChange={(e) => onChange({ ...finding, body: e.target.value })}
        />
      </label>
      <div className="flex flex-wrap gap-2">
        <label className="text-sm">
          <span className="font-medium">Confidence</span>{' '}
          <select
            className={inputClass}
            value={finding.confidence}
            onChange={(e) => onChange({ ...finding, confidence: e.target.value as ReportFinding['confidence'] })}
          >
            <option>low</option>
            <option>medium</option>
            <option>high</option>
          </select>
        </label>
        <label className="text-sm">
          <span className="font-medium">ATT&amp;CK ids</span>{' '}
          <input
            className={inputClass}
            value={finding.attack.join(', ')}
            onChange={(e) =>
              onChange({ ...finding, attack: e.target.value.split(/[\s,]+/).filter(Boolean) })
            }
          />
        </label>
      </div>
      <label className="block text-sm">
        <span className="font-medium">Evidence references (one per line: event|alert|evidence &lt;id&gt;)</span>
        <textarea
          className={`${inputClass} w-full font-mono`}
          rows={2}
          value={finding.refsText}
          onChange={(e) => onChange({ ...finding, refsText: e.target.value })}
        />
      </label>
      {finding.refs.some((r) => r.label) && (
        <ul className="text-xs text-slate-500">
          {finding.refs.map((r) => (
            <li key={`${r.type}-${r.id}`}>
              {r.type} {r.label} {r.ts ? formatUtc(r.ts) : ''}
            </li>
          ))}
        </ul>
      )}
      <Button variant="ghost" onClick={onRemove}>
        Remove finding
      </Button>
    </fieldset>
  )
}

type EditableFinding = ReportFinding & { refsText: string }

function Editor({ report }: { report: ReportDetail }) {
  const { can } = useCase()
  const client = useQueryClient()
  const editable = report.status === 'draft' && can('investigate')
  const [title, setTitle] = useState(report.title)
  const [sections, setSections] = useState<Record<string, string>>(() =>
    Object.fromEntries(report.section_defs.map((s) => [s.name, report.sections[s.name]?.text ?? ''])),
  )
  const [findings, setFindings] = useState<EditableFinding[]>(() =>
    report.findings.map((f) => ({ ...f, refsText: refsToText(f.refs) })),
  )
  const [formError, setFormError] = useState<string | null>(null)
  const save = useMutation({
    mutationFn: () => {
      const out: ReportFinding[] = []
      for (const f of findings) {
        const parsed = parseRefs(f.refsText)
        if (parsed.error) throw new Error(parsed.error)
        out.push({ id: f.id, title: f.title, body: f.body, confidence: f.confidence, attack: f.attack, refs: parsed.refs })
      }
      return api.updateReport(report.id, { expected_revision: report.revision, title, sections, findings: out })
    },
    onSuccess: (r) => {
      setFormError(null)
      client.setQueryData(['report', report.id], r)
    },
    onError: (e) => setFormError(e instanceof Error ? e.message : String(e)),
  })
  return (
    <div className="space-y-3">
      <label className="block text-sm">
        <span className="font-medium">Title</span>
        <input
          className={`${inputClass} w-full`}
          value={title}
          maxLength={300}
          disabled={!editable}
          onChange={(e) => setTitle(e.target.value)}
        />
      </label>
      {report.section_defs.map((sd) => {
        const stored = report.sections[sd.name]
        return (
          <div key={sd.name} className="space-y-1">
            <label className="block text-sm">
              <span className="font-medium">
                {sd.title}
                {sd.required && <span className="text-red-700"> *</span>}
              </span>
              {stored?.ai && (
                <span className="ml-2 rounded bg-amber-100 px-1.5 text-xs text-amber-900">
                  AI-drafted, approved by {stored.ai.reviewed_by_label ?? '?'}
                  {stored.origin === 'ai_edited' ? ', edited' : ''}
                </span>
              )}
              <textarea
                className={`${inputClass} mt-1 w-full`}
                rows={4}
                value={sections[sd.name] ?? ''}
                disabled={!editable}
                onChange={(e) => setSections((s) => ({ ...s, [sd.name]: e.target.value }))}
              />
            </label>
            {editable && sd.ai_draft && can('ai:use') && <SectionAiDraft report={report} section={sd.name} />}
          </div>
        )
      })}
      {report.kind === 'technical' && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">Findings</h3>
          {findings.map((f, i) => (
            <FindingEditor
              key={f.id ?? `new-${i}`}
              finding={f}
              disabled={!editable}
              onChange={(next) => setFindings((all) => all.map((x, j) => (j === i ? next : x)))}
              onRemove={() => setFindings((all) => all.filter((_, j) => j !== i))}
            />
          ))}
          {editable && (
            <Button
              onClick={() =>
                setFindings((all) => [
                  ...all,
                  { title: '', body: '', confidence: 'medium', attack: [], refs: [], refsText: '' },
                ])
              }
            >
              Add finding
            </Button>
          )}
        </div>
      )}
      {editable && (
        <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending}>
          Save (revision {report.revision})
        </Button>
      )}
      {formError && (
        <p role="alert" className="text-sm text-red-700">
          {formError}
        </p>
      )}
    </div>
  )
}

function ReportView({ id, onOpen }: { id: string; onOpen: (id: string) => void }) {
  const { caseId, can, userId } = useCase()
  const client = useQueryClient()
  const q = useQuery({ queryKey: ['report', id], queryFn: ({ signal }) => api.report(id, signal) })
  const [preview, setPreview] = useState(false)
  const [verify, setVerify] = useState<ReportVerify | null>(null)
  const [reason, setReason] = useState('')
  const done = (r: ReportDetail) => {
    client.setQueryData(['report', r.id], r)
    void client.invalidateQueries({ queryKey: ['reports', caseId] })
  }
  const action = useMutation({
    mutationFn: (a: 'qa' | 'approve' | 'sign') => api.reportAction(id, a),
    onSuccess: done,
  })
  const submit = useMutation({ mutationFn: (rev: number) => api.submitReport(id, rev), onSuccess: done })
  const back = useMutation({ mutationFn: () => api.returnReport(id, reason), onSuccess: done })
  const version = useMutation({
    mutationFn: () => api.reportAction(id, 'versions'),
    onSuccess: (r) => {
      done(r)
      onOpen(r.id)
    },
  })
  const check = useMutation({ mutationFn: () => api.verifyReport(id), onSuccess: setVerify })
  const download = useMutation({
    mutationFn: (format: string) => api.reportDownload(id, format),
    onSuccess: ({ blob, filename }) => saveBlob(blob, filename),
  })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const r = q.data
  const errors = action.error ?? submit.error ?? back.error ?? version.error ?? check.error ?? download.error
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-semibold">{r.title}</span>
        <span className="rounded bg-slate-200 px-1.5 text-xs dark:bg-slate-700">{STATUS_TEXT[r.status]}</span>
        <span>v{r.version}</span>
        <span className="font-mono text-xs" title={r.context_sha256}>
          snapshot {shortHash(r.context_sha256, 12)}
        </span>
        {r.sha256 && (
          <span className="font-mono text-xs" title={r.sha256}>
            manifest {shortHash(r.sha256, 12)}
          </span>
        )}
      </div>
      <div className="flex flex-wrap gap-1">
        {r.status === 'draft' && can('investigate') && (
          <>
            <Button onClick={() => action.mutate('qa')}>Run QA</Button>
            <Button variant="primary" onClick={() => submit.mutate(r.revision)}>
              Submit for review
            </Button>
          </>
        )}
        {r.status === 'in_review' && can('approve') && r.submitted_by !== userId && (
          <Button variant="primary" onClick={() => action.mutate('approve')}>
            Approve
          </Button>
        )}
        {r.status === 'approved' && can('approve') && (
          <Button variant="primary" onClick={() => action.mutate('sign')}>
            Sign
          </Button>
        )}
        {r.status === 'signed' && <Button onClick={() => check.mutate()}>Verify</Button>}
        {can('investigate') && <Button onClick={() => version.mutate()}>New version</Button>}
        <Button onClick={() => setPreview((p) => !p)} aria-expanded={preview}>
          {preview ? 'Hide preview' : 'Preview'}
        </Button>
        {r.formats.map((f) => (
          <Button key={f} variant="ghost" onClick={() => download.mutate(f)}>
            {f.toUpperCase()}
          </Button>
        ))}
      </div>
      {(r.status === 'in_review' || r.status === 'approved') && (can('approve') || r.submitted_by === userId) && (
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="block font-medium">Reason to return to draft</span>
            <input className={inputClass} value={reason} onChange={(e) => setReason(e.target.value)} />
          </label>
          <Button onClick={() => back.mutate()} disabled={!reason.trim()}>
            Return to draft
          </Button>
        </div>
      )}
      {r.status === 'in_review' && r.submitted_by === userId && (
        <p className="text-xs text-slate-500">You submitted this report; someone else must approve it.</p>
      )}
      <ErrorMessage error={errors} />
      {r.qa && (
        <div role="status" className="text-sm">
          <p className={r.qa.ok ? 'text-emerald-700' : 'font-semibold text-red-700'}>
            QA {r.qa.ok ? 'passed' : 'failed'} (revision {r.qa.revision})
          </p>
          <ul className="list-disc pl-5">
            {r.qa.errors.map((e, i) => (
              <li key={`e${i}`} className="text-red-700">
                {e.message}
              </li>
            ))}
            {r.qa.warnings.map((w, i) => (
              <li key={`w${i}`} className="text-amber-800">
                {w.message}
              </li>
            ))}
          </ul>
        </div>
      )}
      {verify && <VerifyResultView result={verify} />}
      {preview && <Preview id={r.id} revision={r.revision} status={r.status} />}
      <Editor key={`${r.id}-${r.revision}-${r.status}`} report={r} />
    </div>
  )
}

export function ReportsTab() {
  const { caseId, can } = useCase()
  const list = useQuery({ queryKey: ['reports', caseId], queryFn: ({ signal }) => api.reports(caseId, signal) })
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div className="space-y-4">
      <Panel title="Reports">
        {list.isPending && <Loading />}
        <ErrorMessage error={list.error} />
        {list.data && list.data.items.length === 0 && <p className="text-sm text-slate-500">No reports yet.</p>}
        {list.data && list.data.items.length > 0 && (
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Reports</caption>
            <thead className="text-xs text-slate-500 uppercase">
              <tr>
                <th scope="col">Title</th>
                <th scope="col">Kind</th>
                <th scope="col">Version</th>
                <th scope="col">Status</th>
                <th scope="col">Created</th>
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((r) => (
                <tr key={r.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td>
                    <Button variant="ghost" onClick={() => setOpen(r.id)} aria-current={open === r.id ? 'true' : undefined}>
                      {r.title}
                    </Button>
                  </td>
                  <td>{r.kind}</td>
                  <td>v{r.version}</td>
                  <td>{STATUS_TEXT[r.status]}</td>
                  <td>{formatUtc(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {can('investigate') && <CreateForm onCreated={setOpen} />}
      </Panel>
      {open && (
        <Panel title="Report">
          <ReportView key={open} id={open} onOpen={setOpen} />
        </Panel>
      )}
    </div>
  )
}
