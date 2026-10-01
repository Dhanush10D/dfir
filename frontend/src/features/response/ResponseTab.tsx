import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { ActionRequest, PlaybookRunDetail, RunPlan, RunStep, StepOp, StepPlan } from '@/api/types'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc, shortHash } from '@/lib/format'

/**
 * Response (guide 19): playbooks, runs, steps and four-eyes approvals.
 *
 * Standard profile: there is no remote agent. Endpoint actions (`agent.*`) are never executed by
 * the platform; the UI says so in words ("NOT EXECUTED") and asks a person to record what was
 * done by hand. Everything here renders as plain React text; the server enforces every rule the
 * buttons mirror (RBAC, four eyes, expiry, closed cases).
 */

const STEP_STATUS: Record<RunStep['status'], string> = {
  pending: 'Open',
  awaiting_approval: 'Awaiting approval',
  approved: 'Approved, not run yet',
  not_executed: 'NOT EXECUTED by the platform',
  failed: 'Failed',
  done: 'Done',
  skipped: 'Skipped',
}

const OUTCOME: Record<string, string> = {
  completed: 'completed',
  completed_manually: 'completed by hand (recorded by a person)',
  not_executed: 'not executed',
  failed: 'failed',
  skipped: 'skipped',
}

const PARAMS: Record<string, { name: string; label: string; kind: 'text' | 'int' }[]> = {
  'agent.isolate_host': [{ name: 'host', label: 'Host', kind: 'text' }],
  'agent.kill_process': [
    { name: 'host', label: 'Host', kind: 'text' },
    { name: 'pid', label: 'PID (optional)', kind: 'int' },
    { name: 'process', label: 'Process (optional)', kind: 'text' },
  ],
  'agent.disable_account': [
    { name: 'account', label: 'Account', kind: 'text' },
    { name: 'host', label: 'Host (optional)', kind: 'text' },
  ],
  'agent.memory_dump': [{ name: 'host', label: 'Host', kind: 'text' }],
  'agent.collect_triage': [{ name: 'host', label: 'Host', kind: 'text' }],
}

function shortId(id: string | null | undefined): string {
  return id ? id.slice(0, 8) : '-'
}

function PlanView({ plan }: { plan: RunPlan }) {
  return (
    <div role="status" className="mt-3 rounded border border-slate-300 p-3 text-sm dark:border-slate-700">
      <p className="font-semibold">
        Dry run of {plan.playbook.id} v{plan.playbook.version}: nothing was written.
      </p>
      <p>
        {plan.steps.length} steps, {plan.approvals_needed} need approval by a second person. Notifications:{' '}
        {plan.notifications.channels.join(', ') || 'none'}.
      </p>
      <ol className="mt-2 list-decimal pl-5">
        {plan.steps.map((s) => (
          <li key={s.step_key}>
            <span className="font-medium">{s.phase}:</span> {s.text}
            {s.plan && (
              <span className="block text-xs text-slate-600 dark:text-slate-400">
                {s.plan.title}
                {s.plan.requires_approval ? ' (approval required)' : ''}. {s.plan.effect}
              </span>
            )}
          </li>
        ))}
      </ol>
    </div>
  )
}

function StartForm({ onStarted }: { onStarted: (id: string) => void }) {
  const { caseId } = useCase()
  const client = useQueryClient()
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: ({ signal }) => api.playbooks(signal) })
  const [playbookId, setPlaybookId] = useState('')
  const [alertId, setAlertId] = useState('')
  const [plan, setPlan] = useState<RunPlan | null>(null)
  const enabled = (playbooks.data?.items ?? []).filter((p) => p.enabled)
  const chosen = playbookId || enabled[0]?.id || ''
  const start = useMutation({
    mutationFn: () => api.startRun(caseId, chosen, alertId.trim() || null),
    onSuccess: (run) => {
      setPlan(null)
      void client.invalidateQueries({ queryKey: ['playbook-runs', caseId] })
      onStarted(run.id)
    },
  })
  const preview = useMutation({
    mutationFn: () => api.planRun(caseId, chosen, alertId.trim() || null),
    onSuccess: setPlan,
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    start.mutate()
  }
  if (playbooks.isPending) return <Loading />
  return (
    <div>
      <form onSubmit={submit} aria-label="Start playbook" className="flex flex-wrap items-end gap-2">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Playbook</span>
          <select className={inputClass} value={chosen} onChange={(e) => setPlaybookId(e.target.value)}>
            {enabled.map((p) => (
              <option key={p.id} value={p.id}>
                {p.id}: {p.title}
              </option>
            ))}
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Triggering alert id (optional)</span>
          <input
            className={`${inputClass} w-80 font-mono`}
            value={alertId}
            maxLength={36}
            pattern="[0-9a-fA-F-]{36}"
            onChange={(e) => setAlertId(e.target.value)}
          />
        </label>
        <Button onClick={() => preview.mutate()} disabled={!chosen || preview.isPending}>
          Dry run
        </Button>
        <Button type="submit" variant="primary" disabled={!chosen || start.isPending}>
          Start playbook
        </Button>
      </form>
      <ErrorMessage error={playbooks.error ?? start.error ?? preview.error} />
      {plan && <PlanView plan={plan} />}
    </div>
  )
}

function RequestInfo({ request }: { request: ActionRequest }) {
  return (
    <p className="text-xs text-slate-600 dark:text-slate-400">
      Request {shortId(request.id)}: {request.status}, asked by user {shortId(request.requested_by)} at{' '}
      {formatUtc(request.requested_at)}, expires {formatUtc(request.expires_at)}
      {request.decided_by && ` · decided by user ${shortId(request.decided_by)} at ${formatUtc(request.decided_at)}`}
      {request.decision_reason && ` · reason: ${request.decision_reason}`}
      {request.executed_by && ` · run by user ${shortId(request.executed_by)} at ${formatUtc(request.executed_at)}`}
      {` · parameters ${JSON.stringify(request.params)} (sha256 ${shortHash(request.params_sha256)})`}
    </p>
  )
}

function Decide({ request, onDone }: { request: ActionRequest; onDone: () => void }) {
  const { can, userId } = useCase()
  const [reason, setReason] = useState('')
  const approve = useMutation({ mutationFn: () => api.approveAction(request.id), onSuccess: onDone })
  const reject = useMutation({ mutationFn: () => api.rejectAction(request.id, reason), onSuccess: onDone })
  const mine = request.requested_by === userId
  const mayApprove = can('approve') && !mine
  const mayReject = can('approve') || (mine && can('investigate'))
  if (request.status !== 'pending') return null
  return (
    <div className="mt-1 flex flex-wrap items-end gap-2">
      {mine && can('approve') && (
        <p className="text-xs text-slate-600 dark:text-slate-400">
          You asked for this action; someone else must approve it (four eyes).
        </p>
      )}
      {mayApprove && (
        <Button variant="primary" disabled={approve.isPending} onClick={() => approve.mutate()}>
          Approve
        </Button>
      )}
      {mayReject && (
        <>
          <label className="text-sm">
            <span className="mb-1 block font-medium">Reason</span>
            <input className={inputClass} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} />
          </label>
          <Button variant="danger" disabled={reject.isPending || !reason.trim()} onClick={() => reject.mutate()}>
            {mine ? 'Withdraw' : 'Reject'}
          </Button>
        </>
      )}
      <ErrorMessage error={approve.error ?? reject.error} />
    </div>
  )
}

function StepRow({ run, step, onChanged }: { run: PlaybookRunDetail; step: RunStep; onChanged: () => void }) {
  const { can } = useCase()
  const [notes, setNotes] = useState('')
  const [values, setValues] = useState<Record<string, string>>({})
  const [plan, setPlan] = useState<StepPlan | null>(null)
  const active = run.status === 'running' && can('investigate')
  const fields = step.action ? (PARAMS[step.action] ?? []) : []

  function params(): Record<string, string | number> {
    const out: Record<string, string | number> = {}
    for (const f of fields) {
      const raw = (values[f.name] ?? '').trim()
      if (!raw) continue
      out[f.name] = f.kind === 'int' ? Number.parseInt(raw, 10) : raw
    }
    return out
  }

  const op = useMutation({
    mutationFn: (kind: StepOp) =>
      api.stepOp(run.id, step.step_key, {
        op: kind,
        notes: notes.trim() || null,
        ...(kind === 'request' || (kind === 'execute' && step.status !== 'approved') ? { params: params() } : {}),
      }),
    onSuccess: () => {
      setNotes('')
      setPlan(null)
      onChanged()
    },
  })
  const dry = useMutation({
    mutationFn: () => api.planStep(run.id, step.step_key, step.requires_approval ? 'request' : 'execute', params()),
    onSuccess: setPlan,
  })

  const open = step.status === 'pending' || step.status === 'failed'
  const noExecutor = step.executor === 'none'
  return (
    <li className="border-t border-slate-200 py-2 text-sm dark:border-slate-800">
      <p>
        <span className="font-mono text-xs text-slate-500">{step.step_key}</span> {step.text}{' '}
        <span
          className={`rounded px-1.5 py-0.5 text-xs font-semibold ${
            step.status === 'not_executed' || step.status === 'failed'
              ? 'bg-amber-100 text-amber-900'
              : 'bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100'
          }`}
        >
          {STEP_STATUS[step.status]}
        </span>
      </p>
      {step.kind === 'action' && (
        <p className="text-xs text-slate-600 dark:text-slate-400">
          Action {step.action}
          {step.action_title ? ` (${step.action_title})` : ''}
          {step.requires_approval ? ' · needs approval by a second person' : ''}
          {noExecutor ? ' · the platform cannot execute this action (no remote agent in the Standard profile)' : ''}
        </p>
      )}
      {step.status === 'not_executed' && (
        <p role="status" className="font-medium text-amber-800 dark:text-amber-300">
          Nothing was done on any endpoint. Carry the action out by hand and record it below.
        </p>
      )}
      {step.outcome && (
        <p className="text-xs">
          Outcome: {OUTCOME[step.outcome] ?? step.outcome}
          {step.completed_by && ` · by user ${shortId(step.completed_by)} at ${formatUtc(step.completed_at)}`}
          {!step.completed_by && step.updated_by && ` · by user ${shortId(step.updated_by)} at ${formatUtc(step.updated_at)}`}
        </p>
      )}
      {step.notes && <p className="whitespace-pre-wrap text-xs">Notes: {step.notes}</p>}
      {step.request && <RequestInfo request={step.request} />}
      {step.request && run.status === 'running' && <Decide request={step.request} onDone={onChanged} />}
      {active && (
        <div className="mt-1 flex flex-wrap items-end gap-2">
          {step.kind === 'action' &&
            open &&
            fields.map((f) => (
              <label key={f.name} className="text-sm">
                <span className="mb-1 block font-medium">{f.label}</span>
                <input
                  className={inputClass}
                  value={values[f.name] ?? ''}
                  maxLength={255}
                  inputMode={f.kind === 'int' ? 'numeric' : 'text'}
                  onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
                />
              </label>
            ))}
          {(step.kind === 'manual' ? step.status === 'pending' : step.status === 'not_executed') || open ? (
            <label className="text-sm">
              <span className="mb-1 block font-medium">Notes</span>
              <input className={`${inputClass} w-72`} value={notes} maxLength={4000} onChange={(e) => setNotes(e.target.value)} />
            </label>
          ) : null}
          {step.kind === 'manual' && step.status === 'pending' && (
            <Button variant="primary" disabled={op.isPending} onClick={() => op.mutate('complete')}>
              Mark done
            </Button>
          )}
          {step.kind === 'action' && open && (
            <Button disabled={dry.isPending} onClick={() => dry.mutate()}>
              Dry run
            </Button>
          )}
          {step.kind === 'action' && open && step.requires_approval && (
            <Button variant="primary" disabled={op.isPending} onClick={() => op.mutate('request')}>
              Request approval
            </Button>
          )}
          {step.kind === 'action' && ((open && !step.requires_approval) || step.status === 'approved') && (
            <Button variant="primary" disabled={op.isPending} onClick={() => op.mutate('execute')}>
              {noExecutor ? 'Record attempt (will not execute)' : 'Execute'}
            </Button>
          )}
          {step.status === 'not_executed' && (
            <Button variant="primary" disabled={op.isPending || !notes.trim()} onClick={() => op.mutate('complete')}>
              Record manual completion
            </Button>
          )}
          {(open || step.status === 'not_executed') && (
            <Button disabled={op.isPending || !notes.trim()} onClick={() => op.mutate('skip')}>
              Skip (reason in notes)
            </Button>
          )}
        </div>
      )}
      {plan?.plan && (
        <p role="status" className="mt-1 text-xs">
          Dry run, nothing changed: {plan.plan.title}. {plan.plan.effect}
          {plan.plan.missing_params.length > 0 && ` Missing: ${plan.plan.missing_params.join(', ')}.`}
        </p>
      )}
      <ErrorMessage error={op.error ?? dry.error} />
    </li>
  )
}

function RunView({ runId }: { runId: string }) {
  const { caseId, can } = useCase()
  const client = useQueryClient()
  const [reason, setReason] = useState('')
  const run = useQuery({ queryKey: ['playbook-run', runId], queryFn: ({ signal }) => api.playbookRun(runId, signal) })
  const refresh = () => {
    void client.invalidateQueries({ queryKey: ['playbook-run', runId] })
    void client.invalidateQueries({ queryKey: ['playbook-runs', caseId] })
    void client.invalidateQueries({ queryKey: ['action-requests', caseId] })
  }
  const cancel = useMutation({ mutationFn: () => api.cancelRun(runId, reason), onSuccess: refresh })
  if (run.isPending) return <Loading />
  if (run.error) return <ErrorMessage error={run.error} />
  const data = run.data
  const phases = [...new Set(data.steps.map((s) => s.phase))]
  return (
    <div className="mt-3">
      <h3 className="text-sm font-semibold">
        {data.playbook_id} v{data.playbook_version}: {data.title} ({data.status})
      </h3>
      <p className="text-xs text-slate-600 dark:text-slate-400">
        Started {formatUtc(data.started_at)} by user {shortId(data.started_by)}
        {data.alert_id ? ` · triggered by alert ${data.alert_id}` : ' · no triggering alert'}
        {data.finished_at ? ` · finished ${formatUtc(data.finished_at)}` : ''}
      </p>
      {phases.map((phase) => (
        <section key={phase} aria-label={phase} className="mt-2">
          <h4 className="text-sm font-medium">{phase}</h4>
          <ul>
            {data.steps
              .filter((s) => s.phase === phase)
              .map((s) => (
                <StepRow key={s.id} run={data} step={s} onChanged={refresh} />
              ))}
          </ul>
        </section>
      ))}
      {data.status === 'running' && can('investigate') && (
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="mb-1 block font-medium">Cancel run: reason</span>
            <input className={inputClass} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} />
          </label>
          <Button variant="danger" disabled={cancel.isPending || !reason.trim()} onClick={() => cancel.mutate()}>
            Cancel run
          </Button>
          <ErrorMessage error={cancel.error} />
        </div>
      )}
    </div>
  )
}

function Approvals({ onOpen }: { onOpen: (runId: string) => void }) {
  const { caseId } = useCase()
  const client = useQueryClient()
  const q = useQuery({
    queryKey: ['action-requests', caseId],
    queryFn: ({ signal }) => api.actionRequests(caseId, signal),
  })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const pending = q.data.items.filter((r) => r.status === 'pending')
  if (pending.length === 0) return <p className="text-sm text-slate-500">No approvals are waiting.</p>
  return (
    <ul className="space-y-2 text-sm">
      {pending.map((r) => (
        <li key={r.id}>
          <p>
            <span className="font-medium">{r.action}</span>{' '}
            <Button variant="ghost" onClick={() => onOpen(r.run_id)}>
              open run {shortId(r.run_id)}
            </Button>
          </p>
          <RequestInfo request={r} />
          <Decide
            request={r}
            onDone={() => {
              void client.invalidateQueries({ queryKey: ['action-requests', caseId] })
              void client.invalidateQueries({ queryKey: ['playbook-run', r.run_id] })
            }}
          />
        </li>
      ))}
    </ul>
  )
}

export function ResponseTab() {
  const { caseId, can } = useCase()
  const [selected, setSelected] = useState<string | null>(null)
  const runs = useQuery({
    queryKey: ['playbook-runs', caseId],
    queryFn: ({ signal }) => api.playbookRuns(caseId, signal),
  })
  return (
    <div className="space-y-3">
      <Panel title="Playbooks">
        {can('investigate') ? (
          <StartForm onStarted={setSelected} />
        ) : (
          <p className="text-sm text-slate-500">You can read the response of this case; you cannot change it.</p>
        )}
      </Panel>
      <Panel title="Approvals waiting">
        <Approvals onOpen={setSelected} />
      </Panel>
      <Panel title="Playbook runs">
        {runs.isPending && <Loading />}
        <ErrorMessage error={runs.error} />
        {runs.data && runs.data.items.length === 0 && <p className="text-sm text-slate-500">No playbook has been started.</p>}
        <ul className="text-sm">
          {(runs.data?.items ?? []).map((r) => (
            <li key={r.id}>
              <Button variant="ghost" aria-pressed={selected === r.id} onClick={() => setSelected(r.id)}>
                {r.playbook_id}: {r.title}
              </Button>{' '}
              <span className="text-slate-600 dark:text-slate-400">
                {r.status} · started {formatUtc(r.started_at)}
              </span>
            </li>
          ))}
        </ul>
        {selected && <RunView key={selected} runId={selected} />}
      </Panel>
    </div>
  )
}
