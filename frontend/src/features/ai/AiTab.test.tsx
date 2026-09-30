import { fireEvent, screen, waitFor } from '@testing-library/react'

import type { AiInteraction, AiResult } from '@/api/types'
import { AiTab } from '@/features/ai/AiTab'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch, VIEWER } from '@/test/utils'

const STATUS = {
  enabled: true,
  provider: 'anthropic',
  local_only: false,
  configured: true,
  models: { fast: 'claude-haiku-4-5-20251001', strong: 'claude-sonnet-5-5' },
  embedding_model: 'hashing-v1',
  redaction_policy: 'standard',
  prompt_versions: { nlq: 'nlq/v1+abc' },
}

function interaction(over: Partial<AiInteraction> = {}): AiInteraction {
  return {
    id: 'ai-1',
    case_id: CASE_ID,
    user_id: 'u',
    feature: 'chat',
    status: 'valid',
    provider: 'anthropic',
    model: 'claude-sonnet-5-5',
    model_served: 'claude-sonnet-5-5',
    prompt_version: 'chat/v1+0123456789ab',
    prompt_sha256: 'a'.repeat(64),
    input_sha256: 'b'.repeat(64),
    output_sha256: 'c'.repeat(64),
    started_at: '2026-09-30T08:00:00Z',
    created_at: '2026-09-30T08:00:02Z',
    latency_ms: 1200,
    input_tokens: 100,
    output_tokens: 50,
    cost_usd: null,
    citations_valid: true,
    warnings: [],
    error: null,
    accepted: null,
    reviewed_by: null,
    reviewed_at: null,
    review_note: null,
    feedback: null,
    ...over,
  }
}

const EVENT_ID = '0a0a0a0a-1111-2222-3333-444444444444'

function chatResult(over: Partial<AiInteraction> = {}): AiResult {
  return {
    interaction: interaction(over),
    output: {
      status: 'answered',
      answer: 'Bob logged on after <b>failures</b>.',
      key_facts: [{ statement: 'Failed logon for bob', cites: ['E1'] }],
      limitations: 'Retrieved records only.',
    },
    citations: {
      E1: { short_id: 'E1', kind: 'event', id: EVENT_ID, ts: '2026-09-14T08:00:00Z', summary: '4625 bob' },
    },
    problems: [],
    extras: {},
  }
}

function routes(extra: Record<string, (init: RequestInit) => Response> = {}) {
  return routeFetch({
    'GET /api/v1/ai/status': () => jsonResponse(200, STATUS),
    'GET /api/v1/ai/interactions': () => jsonResponse(200, { items: [], total: 0, limit: 50, offset: 0 }),
    ...extra,
  })
}

describe('AI analyst tab', () => {
  it('shows a cited, badged answer rendered as text with an event link', async () => {
    vi.stubGlobal('fetch', routes({ [`POST /api/v1/ai/cases/${CASE_ID}/chat`]: () => jsonResponse(200, chatResult()) }))
    renderInCase(<AiTab />, ANALYST)
    expect(await screen.findByText(/models claude-haiku-4-5-20251001/)).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('What did the attacker do on ws-042?'), {
      target: { value: 'what did bob do?' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Ask' }))
    expect(await screen.findByText('AI-generated')).toBeInTheDocument()
    expect(screen.getByText('validated (schema + citations)')).toBeInTheDocument()
    // model text is plain text: the <b> tag is shown, not interpreted
    expect(screen.getByText('Bob logged on after <b>failures</b>.')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Citation E1' }))
    const link = screen.getByRole('link', { name: 'Open event in timeline' })
    expect(link.getAttribute('href')).toBe(`/cases/${CASE_ID}/timeline?q=id%3A${EVENT_ID}`)
  })

  it('requires acknowledging warnings before accepting and records the review', async () => {
    const warned = chatResult({ warnings: [{ type: 'injection_suspected', record: 'E1', flags: ['delimiter'] }] })
    const review = vi.fn(() => jsonResponse(200, { ...warned.interaction, accepted: true, reviewed_at: '2026-09-30T09:00:00Z' }))
    vi.stubGlobal(
      'fetch',
      routes({
        [`POST /api/v1/ai/cases/${CASE_ID}/chat`]: () => jsonResponse(200, warned),
        'POST /api/v1/ai/interactions/ai-1/review': review,
      }),
    )
    renderInCase(<AiTab />, ANALYST)
    fireEvent.change(await screen.findByPlaceholderText('What did the attacker do on ws-042?'), {
      target: { value: 'q' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Ask' }))
    expect(await screen.findByText(/contains instruction-like text/)).toBeInTheDocument()
    const accept = screen.getByRole('button', { name: 'Accept' })
    expect(accept).toBeDisabled()
    fireEvent.click(screen.getByLabelText('I have read the warnings'))
    fireEvent.click(accept)
    expect(await screen.findByText(/^Accepted/)).toBeInTheDocument()
    const body = JSON.parse(String((review.mock.calls[0] as unknown as [RequestInit])[0].body)) as Record<string, unknown>
    expect(body).toMatchObject({ decision: 'accept', acknowledge_warnings: true })
  })

  it('shows an unverified answer without review controls', async () => {
    const bad: AiResult = { ...chatResult({ status: 'invalid' }), output: { rejected_reply: 'x' }, problems: ['cited ids: E9'] }
    vi.stubGlobal('fetch', routes({ [`POST /api/v1/ai/nlq`]: () => jsonResponse(200, bad) }))
    renderInCase(<AiTab />, ANALYST)
    fireEvent.change(await screen.findByPlaceholderText('failed ssh logins from 203.0.113.50'), {
      target: { value: 'q' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Translate' }))
    expect(await screen.findByText('AI could not produce a verified answer.')).toBeInTheDocument()
    expect(screen.getByText('cited ids: E9')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Accept' })).not.toBeInTheDocument()
  })

  it('offers no AI actions to viewers but shows the history', async () => {
    vi.stubGlobal(
      'fetch',
      routes({
        'GET /api/v1/ai/interactions': () =>
          jsonResponse(200, { items: [interaction({ accepted: true })], total: 1, limit: 50, offset: 0 }),
      }),
    )
    renderInCase(<AiTab />, VIEWER)
    expect(await screen.findByText('Your role on this case cannot use AI features.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/chat · valid · accepted/)).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Ask' })).not.toBeInTheDocument()
  })
})
