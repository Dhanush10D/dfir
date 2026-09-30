import { fireEvent, screen } from '@testing-library/react'

import { ReportsTab } from '@/features/reports/ReportsTab'
import { parseRefs, refsToText } from '@/features/reports/refs'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch, USER_ID, VIEWER } from '@/test/utils'

const HOSTILE = '<img src=x onerror=alert(1)>'
const RID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const EVENT = '12345678-1234-4234-8234-123456789012'

function report(over: Record<string, unknown> = {}) {
  return {
    id: RID,
    case_id: CASE_ID,
    family_id: RID,
    supersedes_id: null,
    version: 1,
    kind: 'technical',
    title: `Report ${HOSTILE}`,
    status: 'draft',
    revision: 3,
    context_sha256: 'c'.repeat(64),
    created_by: USER_ID,
    created_at: '2026-09-30T10:00:00Z',
    updated_by: USER_ID,
    updated_at: '2026-09-30T10:00:00Z',
    submitted_by: null,
    submitted_at: null,
    approved_by: null,
    approved_at: null,
    signed_by: null,
    signed_at: null,
    key_id: null,
    sha256: null,
    sections: {
      executive_summary: {
        text: 'AI text',
        origin: 'ai_approved',
        ai: { interaction_id: 'i1', reviewed_by_label: 'Lee Lead', reviewed_at: null, model: 'm', prompt_version: 'p', output_sha256: null },
      },
    },
    findings: [
      {
        id: 'f1',
        title: `Finding ${HOSTILE}`,
        body: 'body',
        confidence: 'high',
        attack: ['T1110'],
        refs: [{ type: 'event', id: EVENT, label: '4625 on WS01', ts: '2026-09-14T08:00:00Z', summary: 's' }],
        origin: 'analyst',
      },
    ],
    qa: {
      ok: false,
      errors: [{ code: 'section_empty', message: 'Required section Scope is empty.', where: 'scope' }],
      warnings: [],
      revision: 3,
      checked_at: '2026-09-30T10:00:00Z',
    },
    signature: null,
    manifest: null,
    section_defs: [
      { name: 'executive_summary', title: 'Executive summary', required: true, ai_draft: true },
      { name: 'scope', title: 'Scope', required: true, ai_draft: false },
    ],
    formats: ['html', 'pdf', 'json'],
    counts: {},
    truncated: {},
    ...over,
  }
}

function routes(detail: Record<string, unknown>, calls: string[] = []) {
  return routeFetch({
    [`GET /api/v1/cases/${CASE_ID}/reports`]: () => jsonResponse(200, { items: [detail] }),
    [`GET /api/v1/reports/${RID}/preview`]: () =>
      new Response(`<html><body><script>alert(1)</script>${HOSTILE}</body></html>`, {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      }),
    [`GET /api/v1/reports/${RID}`]: () => jsonResponse(200, detail),
    [`POST /api/v1/reports/${RID}/submit`]: (init) => {
      calls.push(String(init.body))
      return jsonResponse(409, { error: { code: 'qa_failed', message: 'The report does not pass QA.', details: {}, request_id: null } })
    },
  })
}

describe('reports tab', () => {
  it('shows reports as text, the AI label, QA errors and a sandboxed preview', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', routes(report(), calls))
    renderInCase(<ReportsTab />, ANALYST)
    const open = await screen.findByRole('button', { name: `Report ${HOSTILE}` })
    expect(document.querySelector('img')).toBeNull()
    fireEvent.click(open)
    expect(await screen.findByText(/AI-drafted, approved by Lee Lead/)).toBeInTheDocument()
    expect(screen.getByText('Required section Scope is empty.')).toBeInTheDocument()
    expect(screen.getByDisplayValue(`event ${EVENT}`)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Draft with AI' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Preview' }))
    const frame = (await screen.findByTitle('Report preview')) as HTMLIFrameElement
    expect(frame.getAttribute('sandbox')).toBe('')
    expect(frame.getAttribute('srcdoc')).toContain('<script>')  // inert inside the sandbox
    expect(document.querySelector('script')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Submit for review' }))
    expect(await screen.findByText(/does not pass QA/)).toBeInTheDocument()
    expect(JSON.parse(calls[0]!)).toEqual({ expected_revision: 3 })
  })

  it('is read-only for viewers', async () => {
    vi.stubGlobal('fetch', routes(report()))
    renderInCase(<ReportsTab />, VIEWER)
    fireEvent.click(await screen.findByRole('button', { name: `Report ${HOSTILE}` }))
    expect(await screen.findByText('Executive summary')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Submit for review' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Create report' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Save/ })).toBeNull()
    expect(screen.getByDisplayValue('AI text')).toBeDisabled()
  })

  it('hides approve from the submitter (four eyes)', async () => {
    vi.stubGlobal('fetch', routes(report({ status: 'in_review', submitted_by: USER_ID })))
    renderInCase(<ReportsTab />, [...ANALYST, 'approve'])
    fireEvent.click(await screen.findByRole('button', { name: `Report ${HOSTILE}` }))
    expect(await screen.findByText(/someone else must approve it/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull()
  })
})

describe('reference parsing', () => {
  it('round-trips references and rejects anything else', () => {
    const refs = [{ type: 'alert' as const, id: EVENT }]
    expect(parseRefs(refsToText(refs))).toEqual({ refs, error: null })
    expect(parseRefs(`event: ${EVENT.toUpperCase()}\n\n`).refs[0]).toEqual({ type: 'event', id: EVENT })
    expect(parseRefs('javascript:alert(1)').error).toMatch(/Not a reference/)
    expect(parseRefs(`note ${EVENT}`).error).toMatch(/Not a reference/)
  })
})
