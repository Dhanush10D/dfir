import { QueryClient } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { setAccessToken } from '@/api/client'
import type { AppNotification } from '@/api/types'
import { Providers } from '@/app/providers'
import { NotificationsPage } from '@/features/integrations/NotificationsPage'
import { CASE_ID, jsonResponse, routeFetch } from '@/test/utils'

const HOSTILE = '<img src=x onerror=alert(1)>'

function note(over: Partial<AppNotification> = {}): AppNotification {
  return {
    id: 'n1',
    kind: 'playbook.approval_requested',
    payload: {
      title: 'Approval requested in case IR-2026-0001',
      case_id: CASE_ID,
      tab: 'response',
      fields: [
        { label: 'Action', value: 'agent.isolate_host' },
        { label: 'Step', value: HOSTILE },
      ],
    },
    case_id: CASE_ID,
    read_at: null,
    created_at: '2026-10-01T08:00:00Z',
    ...over,
  }
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Providers client={client}>
      <NotificationsPage />
    </Providers>,
  )
}

function routes(items: AppNotification[], calls: string[] = []) {
  const unread = () => items.filter((n) => !n.read_at).length
  return routeFetch({
    'GET /api/v1/notifications': () => jsonResponse(200, { items, unread: unread() }),
    'POST /api/v1/notifications/read-all': () => {
      calls.push('read-all')
      items = items.map((n) => ({ ...n, read_at: '2026-10-01T09:00:00Z' }))
      return jsonResponse(204, undefined)
    },
    'POST /api/v1/notifications/n1/read': () => {
      calls.push('read n1')
      items = items.map((n) => (n.id === 'n1' ? { ...n, read_at: '2026-10-01T09:00:00Z' } : n))
      return jsonResponse(200, items[0])
    },
  })
}

beforeEach(() => {
  setAccessToken('access-1')
})

describe('NotificationsPage', () => {
  it('shows fields as text and links to the validated case tab', async () => {
    vi.stubGlobal('fetch', routes([note()]))
    renderPage()
    expect(await screen.findByText(/Approval requested in case IR-2026-0001/)).toBeInTheDocument()
    expect(screen.getByText(/Action: agent\.isolate_host/)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull() // a hostile field value stays text
    expect(screen.getByText('1 unread')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open case' }).getAttribute('href')).toBe(`/cases/${CASE_ID}/response`)
  })

  it('never links a case id or tab that does not validate', async () => {
    vi.stubGlobal(
      'fetch',
      routes([
        note({ id: 'n2', case_id: null, payload: { title: 'Bad id', case_id: 'javascript:alert(1)//aaaaaaaaaaaaaaaaa' } }),
        note({ id: 'n3', payload: { title: 'Bad tab', case_id: CASE_ID, tab: '../../admin' } }),
      ]),
    )
    renderPage()
    expect(await screen.findByText(/Bad id/)).toBeInTheDocument()
    const links = screen.getAllByRole('link', { name: 'Open case' })
    expect(links).toHaveLength(1) // only the notification with a valid case id
    expect(links[0]!.getAttribute('href')).toBe(`/cases/${CASE_ID}/overview`) // unknown tab -> overview
    expect(document.querySelector('a[href^="javascript"]')).toBeNull()
  })

  it('marks one and then all notifications read', async () => {
    const calls: string[] = []
    vi.stubGlobal('fetch', routes([note(), note({ id: 'n2', payload: { title: 'Second one' } })], calls))
    renderPage()
    expect(await screen.findByText('2 unread')).toBeInTheDocument()
    fireEvent.click(screen.getAllByRole('button', { name: 'Mark read' })[0]!)
    await waitFor(() => expect(calls).toContain('read n1'))
    expect(await screen.findByText('1 unread')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Mark all read' }))
    await waitFor(() => expect(calls).toContain('read-all'))
    expect(await screen.findByText('0 unread')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Mark read' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Mark all read' })).toBeDisabled()
  })

  it('says so when there are no notifications', async () => {
    vi.stubGlobal('fetch', routes([]))
    renderPage()
    expect(await screen.findByText('No notifications.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Mark all read' })).toBeDisabled()
  })
})
