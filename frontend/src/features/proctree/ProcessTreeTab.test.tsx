import { fireEvent, screen, within } from '@testing-library/react'

import type { ProcessNode } from '@/api/types'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch } from '@/test/utils'

import { ProcessTreeTab } from './ProcessTreeTab'

function node(key: string, name: string, extra: Partial<ProcessNode> = {}): ProcessNode {
  return {
    key,
    pid: Number(key.slice(1)),
    ppid: null,
    name,
    kind: 'created',
    ts: '2026-09-14T02:10:00Z',
    image: null,
    cmdline: null,
    user: 'root',
    event_id: null,
    parent: null,
    depth: 0,
    children: 0,
    flags: [],
    alerts: 0,
    ...extra,
  }
}

const NODES: ProcessNode[] = [
  node('p100', 'nginx', { children: 1 }),
  node('p200', 'bash', { parent: 'p100', ppid: 100, depth: 1, alerts: 2, cmdline: 'bash -i' }),
  node('p300', 'cron', { kind: 'observed' }),
]

function setup() {
  vi.stubGlobal(
    'fetch',
    routeFetch({
      [`POST /api/v1/cases/${CASE_ID}/events/facets`]: () =>
        jsonResponse(200, { fields: { host: [{ value: 'web01', count: 3 }] } }),
      [`GET /api/v1/cases/${CASE_ID}/process-tree`]: () =>
        jsonResponse(200, { host: 'web01', nodes: NODES, roots: ['p100', 'p300'], truncated: false, cycles_broken: 0, depth_capped: 0 }),
    }),
  )
  renderInCase(<ProcessTreeTab />, ANALYST)
}

describe('process tree tab', () => {
  it('picks a host, collapses branches and filters to alerting processes', async () => {
    setup()
    fireEvent.click(await screen.findByRole('button', { name: /web01/ }))
    const table = await screen.findByRole('table', { name: 'Processes on web01' })
    expect(within(table).getByText('bash -i')).toBeInTheDocument()
    expect(within(table).getByText('2 alerts')).toBeInTheDocument()

    fireEvent.click(within(table).getByRole('button', { name: /Collapse nginx/ }))
    expect(within(table).queryByText('bash')).toBeNull()
    fireEvent.click(within(table).getByRole('button', { name: /Expand nginx/ }))
    expect(within(table).getByText('bash')).toBeInTheDocument()

    // The alert filter keeps the alerting child and its parent, and drops the unrelated root.
    fireEvent.click(screen.getByLabelText('Only processes with alerts or warnings'))
    expect(within(table).getByText('nginx')).toBeInTheDocument()
    expect(within(table).getByText('bash')).toBeInTheDocument()
    expect(within(table).queryByText('cron')).toBeNull()
  })
})
