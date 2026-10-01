import { QueryClient } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { setAccessToken } from '@/api/client'
import { Providers } from '@/app/providers'
import { AuthProvider } from '@/auth/AuthContext'
import { IntegrationsPage } from '@/features/integrations/IntegrationsPage'
import { NotificationsPage } from '@/features/integrations/NotificationsPage'
import { CASE_ID, jsonResponse, routeFetch } from '@/test/utils'

const HOSTILE = '<img src=x onerror=alert(1)>'
const IID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
const SECRET = 'whsec-super-secret-value-0123456789abcdef'
const TOKENS = {
  access_token: 'access-1',
  token_type: 'bearer',
  expires_at: '2026-10-01T08:15:00Z',
  refresh_token: null,
  refresh_expires_at: '2026-10-08T08:00:00Z',
}

function me(permissions: string[]) {
  return {
    user: { id: 'u1', email: 'a@x.test', display_name: 'Ada Admin', role: 'admin', mfa_enabled: true },
    permissions,
    auth_method: 'jwt',
  }
}

const HOOK = {
  id: IID,
  type: 'webhook_out',
  name: `soc-hook ${HOSTILE}`,
  enabled: true,
  config: { url: 'javascript:alert(1)', events: ['alert.created'] },
  case_id: null,
  has_secret: true,
  secret_fingerprint: 'abcdef012345',
  secret_key_id: 'kek-1',
  last_status: `http_500 ${HOSTILE}`,
  last_status_at: '2026-10-01T08:00:00Z',
  created_at: '2026-10-01T07:00:00Z',
  updated_at: '2026-10-01T08:00:00Z',
}

function renderPage(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Providers client={client}>
      <AuthProvider>{ui}</AuthProvider>
    </Providers>,
  )
}

function routes(permissions: string[], calls: { url: string; body: string }[] = []) {
  return routeFetch({
    'POST /api/v1/auth/refresh': () => jsonResponse(200, TOKENS),
    'GET /api/v1/me': () => jsonResponse(200, me(permissions)),
    'GET /api/v1/integrations': () => jsonResponse(200, { items: [HOOK], secrets_available: true }),
    [`GET /api/v1/integrations/${IID}/deliveries`]: () =>
      jsonResponse(200, {
        outbound: [
          {
            id: 'd1',
            event_id: 'e1',
            event_type: 'alert.created',
            kind: 'webhook_out',
            status: 'failed',
            attempts: 5,
            max_attempts: 5,
            next_attempt_at: null,
            last_error: `blocked:address_private ${HOSTILE}`,
            response_status: null,
            created_at: '2026-10-01T08:00:00Z',
            delivered_at: null,
          },
        ],
        inbound: [],
      }),
    'POST /api/v1/integrations': (init) => {
      calls.push({ url: 'create', body: String(init.body) })
      return jsonResponse(201, { ...HOOK, id: 'new', name: 'new-hook', enabled: false })
    },
    [`PATCH /api/v1/integrations/${IID}`]: (init) => {
      calls.push({ url: 'patch', body: String(init.body) })
      return jsonResponse(200, HOOK)
    },
    'GET /api/v1/notifications': () =>
      jsonResponse(200, {
        unread: 1,
        items: [
          {
            id: 'n1',
            kind: 'alert.created',
            payload: {
              title: `New alert ${HOSTILE}`,
              case_id: CASE_ID,
              tab: 'javascript:alert(1)',
              fields: [{ label: 'Severity', value: 'high' }],
            },
            case_id: CASE_ID,
            read_at: null,
            created_at: '2026-10-01T08:00:00Z',
          },
        ],
      }),
    'POST /api/v1/notifications/n1/read': (init) => {
      calls.push({ url: 'read', body: String(init.body) })
      return jsonResponse(200, {})
    },
  })
}

beforeEach(() => {
  setAccessToken(null)
})

describe('integrations page', () => {
  it('never shows a secret: write-only password inputs, fingerprint only', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(['users:manage'], calls))
    renderPage(<IntegrationsPage />)
    expect(await screen.findByText(/set \(fingerprint abcdef012345, key kek-1\)/)).toBeInTheDocument()
    // Hostile server text stays text; a javascript: URL in the config is not a link.
    expect(document.querySelector('img')).toBeNull()
    expect(document.querySelector('a[href^="javascript"]')).toBeNull()
    const secretInputs = Array.from(document.querySelectorAll('input[type="password"]')) as HTMLInputElement[]
    expect(secretInputs.length).toBe(2) // the new-integration form and the row
    for (const input of secretInputs) {
      expect(input.value).toBe('') // never prefilled from the server
      expect(input.getAttribute('autocomplete')).toBe('new-password')
    }

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'new-hook' } })
    fireEvent.change(screen.getByLabelText('URL (https)'), { target: { value: 'https://hooks.example.test/x' } })
    fireEvent.click(screen.getByLabelText('alert.created'))
    fireEvent.change(screen.getByLabelText('Signing secret (32+ characters)'), { target: { value: SECRET } })
    fireEvent.click(screen.getByRole('button', { name: 'Create (disabled)' }))
    await waitFor(() => expect(calls.some((c) => c.url === 'create')).toBe(true))
    const sent = JSON.parse(calls.find((c) => c.url === 'create')!.body)
    expect(sent).toMatchObject({
      type: 'webhook_out',
      name: 'new-hook',
      enabled: false,
      secret: { signing_secret: SECRET },
      config: { url: 'https://hooks.example.test/x', events: ['alert.created'], include_details: false },
    })
    // After sending, the secret is gone from the page.
    await waitFor(() =>
      expect((screen.getByLabelText('Signing secret (32+ characters)') as HTMLInputElement).value).toBe(''),
    )
    expect(document.body.textContent).not.toContain(SECRET)

    fireEvent.click(screen.getByRole('button', { name: 'Delivery log' }))
    expect(await screen.findByText(/blocked:address_private/)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(calls.some((c) => c.url === 'patch')).toBe(true))
    expect(JSON.parse(calls.find((c) => c.url === 'patch')!.body)).toEqual({ enabled: false })
  })

  it('is not available to non-admins', async () => {
    const fetchMock = routes(['case:read', 'investigate'])
    vi.stubGlobal('fetch', fetchMock)
    renderPage(<IntegrationsPage />)
    expect(await screen.findByText('Integrations are managed by administrators.')).toBeInTheDocument()
    await waitFor(() => expect(fetchMock.mock.calls.some(([url]) => url === '/api/v1/me')).toBe(true))
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith('/api/v1/integrations'))).toBe(false)
  })
})

describe('notifications page', () => {
  it('renders payloads as text and links only to a validated case path', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(['case:read'], calls))
    renderPage(<NotificationsPage />)
    expect(await screen.findByText(/New alert/)).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    const link = screen.getByRole('link', { name: 'Open case' })
    expect(link.getAttribute('href')).toBe(`/cases/${CASE_ID}/overview`) // the hostile tab was ignored
    expect(screen.getByText('Severity: high')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Mark read' }))
    await waitFor(() => expect(calls.some((c) => c.url === 'read')).toBe(true))
  })
})
