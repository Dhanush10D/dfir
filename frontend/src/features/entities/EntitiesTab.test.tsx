import { fireEvent, screen, within } from '@testing-library/react'

import type { Entity } from '@/api/types'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch } from '@/test/utils'

import { EntitiesTab } from './EntitiesTab'

function entity(id: string, type: string, canonical: string, event_count: number): Entity {
  return { id, case_id: CASE_ID, type, canonical, attributes: {}, first_seen: null, last_seen: null, event_count }
}

const HOST = entity('e-host', 'host', 'web01', 60)
const USER = entity('e-user', 'user', 'root', 11)

describe('entities tab', () => {
  it('lists entities, draws one graph column per type and focuses a clicked entity', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({
        [`GET /api/v1/cases/${CASE_ID}/entities`]: () => jsonResponse(200, { items: [HOST, USER], next_cursor: null }),
        [`GET /api/v1/cases/${CASE_ID}/graph`]: () =>
          jsonResponse(200, {
            nodes: [HOST, USER],
            edges: [{ src_entity: 'e-user', dst_entity: 'e-host', relation: 'logged_on', weight: 5 }],
            truncated: false,
          }),
        'GET /api/v1/entities/e-host': () =>
          jsonResponse(200, { ...HOST, aliases: [], neighbours: [], alert_count: 3, pivot_query: 'host:web01' }),
      }),
    )
    renderInCase(<EntitiesTab />, ANALYST)
    const graph = await screen.findByRole('group', { name: 'Entity graph' })
    expect(within(graph).getByText('user (1)')).toBeInTheDocument()
    expect(within(graph).getByText('host (1)')).toBeInTheDocument()

    fireEvent.click(within(graph).getByRole('button', { name: 'host web01' }))
    expect(await screen.findByRole('link', { name: /Open in timeline/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show whole case' })).toBeInTheDocument()
  })
})
