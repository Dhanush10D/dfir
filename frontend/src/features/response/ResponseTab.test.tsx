import { fireEvent, screen, waitFor } from '@testing-library/react'

import { ResponseTab } from '@/features/response/ResponseTab'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch, USER_ID, VIEWER } from '@/test/utils'

const HOSTILE = '<img src=x onerror=alert(1)>'
const RUN = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const REQ = '12345678-1234-4234-8234-123456789012'
const OTHER = '77777777-6666-4555-8444-333333333333'
const ALERT = '22222222-3333-4444-8555-666666666666'
const ENRICHED = {
  ioc_id: 'i1',
  ioc_type: 'ip',
  value: `203.0.113.9 ${HOSTILE}`,
  provider: 'virustotal',
  status: 'cached',
  verdict: 'malicious',
  score: 0.9,
  summary: { note: HOSTILE },
  fetched_at: '2026-10-01T08:00:00Z',
  expires_at: '2026-10-02T08:00:00Z',
  tlp: null,
  error: null,
}

function request(over: Record<string, unknown> = {}) {
  return {
    id: REQ,
    case_id: CASE_ID,
    run_id: RUN,
    step_id: 's1',
    alert_id: null,
    action: 'agent.isolate_host',
    params: { host: `WS-042 ${HOSTILE}` },
    params_sha256: 'd'.repeat(64),
    status: 'pending',
    requested_by: OTHER,
    requested_at: '2026-10-01T08:00:00Z',
    expires_at: '2026-10-01T12:00:00Z',
    decided_by: null,
    decided_at: null,
    decision_reason: null,
    executed_by: null,
    executed_at: null,
    outcome: null,
    result: null,
    ...over,
  }
}

function step(over: Record<string, unknown> = {}) {
  return {
    id: 's1',
    position: 0,
    phase: 'Containment',
    step_key: 'c1',
    text: `Isolate affected hosts ${HOSTILE}`,
    kind: 'action',
    action: 'agent.isolate_host',
    action_title: 'Isolate a host from the network',
    executor: 'none',
    params: {},
    requires_approval: true,
    status: 'pending',
    outcome: null,
    result: null,
    notes: null,
    completed_by: null,
    completed_at: null,
    updated_by: null,
    updated_at: '2026-10-01T08:00:00Z',
    alert_id: null,
    request: null,
    ...over,
  }
}

function run(steps: unknown[], over: Record<string, unknown> = {}) {
  return {
    id: RUN,
    case_id: CASE_ID,
    playbook_id: 'PB-RANSOMWARE-01',
    playbook_version: 1,
    playbook_sha256: 'e'.repeat(64),
    title: 'Suspected ransomware',
    status: 'running',
    alert_id: null,
    started_by: USER_ID,
    started_at: '2026-10-01T08:00:00Z',
    finished_at: null,
    steps,
    ...over,
  }
}

const PLAYBOOKS = {
  items: [
    {
      id: 'PB-RANSOMWARE-01',
      title: 'Suspected ransomware',
      description: null,
      version: 1,
      enabled: true,
      origin: 'builtin',
      sha256: null,
      trigger: {},
      phases: [],
      notify: {},
      updated_at: '2026-10-01T08:00:00Z',
    },
  ],
}

function routes(detail: Record<string, unknown>, calls: { url: string; body: string }[] = [], pending: unknown[] = []) {
  return routeFetch({
    'GET /api/v1/playbooks': () => jsonResponse(200, PLAYBOOKS),
    [`GET /api/v1/cases/${CASE_ID}/playbook-runs`]: () => jsonResponse(200, { items: [detail] }),
    [`GET /api/v1/cases/${CASE_ID}/action-requests`]: () => jsonResponse(200, { items: pending }),
    [`GET /api/v1/playbook-runs/${RUN}`]: () => jsonResponse(200, detail),
    [`PATCH /api/v1/playbook-runs/${RUN}/steps/c1`]: (init) => {
      calls.push({ url: 'step', body: String(init.body) })
      return jsonResponse(200, detail)
    },
    [`POST /api/v1/cases/${CASE_ID}/playbook-runs`]: (init) => {
      calls.push({ url: 'start', body: String(init.body) })
      return jsonResponse(200, {
        dry_run: true,
        writes: 'none',
        playbook: { id: 'PB-RANSOMWARE-01', version: 1, title: 'Suspected ransomware' },
        alert_id: null,
        steps: [
          {
            position: 0,
            phase: 'Containment',
            step_key: 'c1',
            text: 'Isolate affected hosts',
            kind: 'action',
            action: 'agent.isolate_host',
            requires_approval: true,
            plan: {
              action: 'agent.isolate_host',
              title: 'Isolate a host from the network',
              impact: true,
              requires_approval: true,
              executor: 'none',
              would_execute: false,
              effect: 'Nothing is changed on any endpoint (no remote agent in the Standard profile).',
              params: {},
              missing_params: ['host'],
            },
          },
        ],
        approvals_needed: 1,
        notifications: { event: 'playbook.run_started', channels: ['in_app'], roles: ['lead'] },
      })
    },
    [`GET /api/v1/cases/${CASE_ID}/enrichments`]: () => jsonResponse(200, { items: [ENRICHED] }),
    [`POST /api/v1/cases/${CASE_ID}/iocs/enrich`]: (init) => {
      calls.push({ url: 'enrich', body: String(init.body) })
      return jsonResponse(200, {
        results: [
          ENRICHED,
          { ...ENRICHED, ioc_id: 'i2', value: 'secret.internal.test', status: 'skipped_tlp', tlp: 'amber', verdict: null },
        ],
        counts: { cached: 1, skipped_tlp: 1 },
        truncated: false,
      })
    },
    [`GET /api/v1/alerts/${ALERT}/playbooks`]: () => jsonResponse(200, PLAYBOOKS),
    [`POST /api/v1/action-requests/${REQ}/approve`]: (init) => {
      calls.push({ url: 'approve', body: String(init.body) })
      return jsonResponse(200, request({ status: 'approved' }))
    },
  })
}

async function openRun() {
  fireEvent.click(await screen.findByRole('button', { name: 'PB-RANSOMWARE-01: Suspected ransomware' }))
}

describe('response tab', () => {
  it('shows steps as text and asks for approval with the entered parameters', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(run([step()]), calls))
    renderInCase(<ResponseTab />, ANALYST)
    await openRun()
    expect(await screen.findByText(new RegExp('Isolate affected hosts'))).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull() // hostile step text stayed text
    expect(screen.getByText(/cannot execute this action \(no remote agent/)).toBeInTheDocument()
    // An impactful action offers "Request approval", never a direct "Execute".
    expect(screen.queryByRole('button', { name: 'Execute' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Record attempt/ })).toBeNull()
    fireEvent.change(screen.getByLabelText('Host'), { target: { value: 'WS-042' } })
    fireEvent.click(screen.getByRole('button', { name: 'Request approval' }))
    await waitFor(() => expect(calls.some((c) => c.url === 'step')).toBe(true))
    expect(JSON.parse(calls.find((c) => c.url === 'step')!.body)).toEqual({
      op: 'request',
      notes: null,
      params: { host: 'WS-042' },
    })
  })

  it('a dry run shows the plan and says nothing was written', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(run([step()]), calls))
    renderInCase(<ResponseTab />, ANALYST)
    const form = await screen.findByRole('form', { name: 'Start playbook' })
    fireEvent.click(await screen.findByRole('button', { name: 'Dry run' }))
    expect(await screen.findByText(/nothing was written/)).toBeInTheDocument()
    expect(screen.getByText(/Nothing is changed on any endpoint/)).toBeInTheDocument()
    expect(JSON.parse(calls[0]!.body)).toMatchObject({ playbook_id: 'PB-RANSOMWARE-01', dry_run: true })
    expect(form).toBeInTheDocument()
  })

  it('labels an action the platform did not execute and asks for a manual record', async () => {
    const calls: { url: string; body: string }[] = []
    const notExecuted = step({
      status: 'not_executed',
      outcome: 'not_executed',
      result: { reason: 'no_remote_agent' },
      updated_by: USER_ID,
      request: request({ status: 'finished', outcome: 'not_executed', decided_by: 'x', executed_by: USER_ID }),
    })
    vi.stubGlobal('fetch', routes(run([notExecuted]), calls))
    renderInCase(<ResponseTab />, ANALYST)
    await openRun()
    expect(await screen.findByText('NOT EXECUTED by the platform')).toBeInTheDocument()
    expect(screen.getByText(/Nothing was done on any endpoint/)).toBeInTheDocument()
    expect(screen.queryByText(/isolated/i)).toBeNull() // never claims the host was isolated
    const record = screen.getByRole('button', { name: 'Record manual completion' })
    expect(record).toBeDisabled() // notes are required
    fireEvent.change(screen.getByLabelText('Notes'), { target: { value: 'Done in the EDR console' } })
    fireEvent.click(record)
    await waitFor(() => expect(calls.length).toBe(1))
    expect(JSON.parse(calls[0]!.body)).toEqual({ op: 'complete', notes: 'Done in the EDR console' })
  })

  it('lets an approver decide a request of someone else, with parameters shown as text', async () => {
    const calls: { url: string; body: string }[] = []
    const waiting = step({ status: 'awaiting_approval', request: request() })
    vi.stubGlobal('fetch', routes(run([waiting]), calls, [request()]))
    renderInCase(<ResponseTab />, [...ANALYST, 'approve'])
    const approve = await screen.findByRole('button', { name: 'Approve' })
    expect(document.querySelector('img')).toBeNull() // hostile parameter value stayed text
    fireEvent.click(approve)
    await waitFor(() => expect(calls.some((c) => c.url === 'approve')).toBe(true))
  })

  it('hides approve from the requester (four eyes) and from people without the permission', async () => {
    const own = request({ requested_by: USER_ID })
    vi.stubGlobal('fetch', routes(run([step({ status: 'awaiting_approval', request: own })]), [], [own]))
    const first = renderInCase(<ResponseTab />, [...ANALYST, 'approve'])
    expect((await screen.findAllByText(/someone else must approve it/)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Withdraw' }).length).toBeGreaterThan(0)
    first.unmount()

    vi.stubGlobal('fetch', routes(run([step({ status: 'awaiting_approval', request: request() })]), [], [request()]))
    renderInCase(<ResponseTab />, ANALYST)
    expect(await screen.findByText(/Request 12345678: pending/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Reject' })).toBeNull()
  })

  it('shows cached enrichment verdicts as text and enriches on request', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(run([step()]), calls))
    const first = renderInCase(<ResponseTab />, VIEWER)
    expect(await screen.findByText(/203\.0\.113\.9/)).toBeInTheDocument()
    expect(screen.getByText('malicious')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull() // a hostile indicator value stays text
    expect(screen.queryByRole('button', { name: 'Enrich indicators' })).toBeNull()
    first.unmount()

    renderInCase(<ResponseTab />, ANALYST)
    fireEvent.click(await screen.findByRole('button', { name: 'Enrich indicators' }))
    await waitFor(() => expect(calls.some((c) => c.url === 'enrich')).toBe(true))
    expect(await screen.findByText(/cached: 1, skipped_tlp: 1/)).toBeInTheDocument()
    expect(screen.getByText(/secret\.internal\.test at virustotal: skipped_tlp \(TLP amber\)/)).toBeInTheDocument()
  })

  it('suggests playbooks whose trigger matches the alert', async () => {
    vi.stubGlobal('fetch', routes(run([step()])))
    renderInCase(<ResponseTab />, ANALYST)
    const input = await screen.findByLabelText('Triggering alert id (optional)')
    fireEvent.change(input, { target: { value: ALERT } })
    expect(await screen.findByText(/Suggested for this alert/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'PB-RANSOMWARE-01' })).toBeInTheDocument()
  })

  it('is read-only for viewers and for finished runs', async () => {
    vi.stubGlobal('fetch', routes(run([step(), step({ id: 's2', step_key: 'c2', kind: 'manual', action: null, executor: null, requires_approval: false, text: 'Disable accounts' })])))
    const first = renderInCase(<ResponseTab />, VIEWER)
    await openRun()
    expect(await screen.findByText('Disable accounts', { exact: false })).toBeInTheDocument()
    for (const name of ['Start playbook', 'Request approval', 'Mark done', 'Cancel run', 'Dry run']) {
      expect(screen.queryByRole('button', { name })).toBeNull()
    }
    first.unmount()

    vi.stubGlobal('fetch', routes(run([step()], { status: 'cancelled', finished_at: '2026-10-01T09:00:00Z' })))
    renderInCase(<ResponseTab />, ANALYST)
    await openRun()
    expect(await screen.findByText(/\(cancelled\)/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Request approval' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Cancel run' })).toBeNull()
  })
})
