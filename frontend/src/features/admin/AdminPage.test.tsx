import { QueryClient } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import { setAccessToken } from '@/api/client'
import type { AdminUser } from '@/api/types'
import { Providers } from '@/app/providers'
import { AuthProvider } from '@/auth/AuthContext'
import { AdminPage } from '@/features/admin/AdminPage'
import { CASE_ID, jsonResponse, routeFetch } from '@/test/utils'

const TOKENS = {
  access_token: 'access-1',
  token_type: 'bearer',
  expires_at: '2026-10-01T08:15:00Z',
  refresh_token: null,
  refresh_expires_at: '2026-10-08T08:00:00Z',
}

function user(over: Partial<AdminUser>): AdminUser {
  return {
    id: 'u1',
    email: 'ada@x.test',
    display_name: 'Ada Admin',
    role: 'admin',
    mfa_enabled: false,
    is_active: true,
    failed_logins: 0,
    locked_until: null,
    last_login_at: '2026-10-15T08:00:00Z',
    created_at: '2026-10-01T08:00:00Z',
    ...over,
  }
}

const ADA = user({})
const BOB = user({ id: 'u2', email: 'bob@x.test', display_name: 'Bob Analyst', role: 'analyst', last_login_at: null })

function routes(permissions: string[], calls: { url: string; body: string }[] = []) {
  return routeFetch({
    'POST /api/v1/auth/refresh': () => jsonResponse(200, TOKENS),
    'GET /api/v1/me': () =>
      jsonResponse(200, {
        user: { id: 'u1', email: 'ada@x.test', display_name: 'Ada Admin', role: 'admin', mfa_enabled: false },
        permissions,
        auth_method: 'jwt',
      }),
    'GET /api/v1/users': () => jsonResponse(200, [ADA, BOB]),
    'POST /api/v1/users': (init) => {
      calls.push({ url: 'create', body: String(init.body) })
      return jsonResponse(201, user({ id: 'u3', email: 'cara@x.test', display_name: 'Cara', role: 'analyst' }))
    },
    'GET /api/v1/cases?': () =>
      jsonResponse(200, {
        items: [{ id: CASE_ID, case_number: 'IR-2026-0001', title: 'Test case', status: 'open', severity: 'high' }],
        total: 1,
      }),
    [`GET /api/v1/cases/${CASE_ID}/members`]: () => jsonResponse(200, []),
    [`POST /api/v1/cases/${CASE_ID}/members`]: (init) => {
      calls.push({ url: 'member', body: String(init.body) })
      return jsonResponse(200, [])
    },
    'GET /api/v1/audit': () =>
      jsonResponse(200, {
        items: [{ id: 1, ts: '2026-10-15T08:00:00Z', user_id: 'u1', ip: null, method: 'POST', path: '/x', status: 201, action: 'user.create', object_type: 'user', object_id: 'u2', detail: {} }],
        total: 1,
      }),
    'GET /api/v1/ai/status': () =>
      jsonResponse(200, {
        enabled: true,
        provider: 'openai_compat',
        local_only: false,
        configured: true,
        models: { fast: 'small-model', strong: 'big-model' },
        embedding_model: 'hashing-v1',
        redaction_policy: 'standard',
        prompt_versions: {},
      }),
    'GET /api/v1/health': () => jsonResponse(200, { status: 'ok', service: 'api', version: '0.1.0', env: 'test', time: '2026-10-15T08:00:00Z' }),
  })
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Providers client={client}>
      <AuthProvider>
        <AdminPage />
      </AuthProvider>
    </Providers>,
  )
}

beforeEach(() => {
  setAccessToken(null)
})

describe('admin page', () => {
  it('lists accounts and creates an analyst without asking for the admin password', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(['users:manage'], calls))
    renderPage()
    const table = await screen.findByRole('table', { name: 'Accounts' })
    expect(within(table).getByText('Bob Analyst')).toBeInTheDocument()
    expect(within(table).getByText('never')).toBeInTheDocument()
    expect(await screen.findByText('user.create')).toBeInTheDocument()

    const form = screen.getByRole('form', { name: 'Create account' })
    expect(within(form).queryByLabelText(/Your password/)).toBeNull()
    fireEvent.change(within(form).getByLabelText('Full name'), { target: { value: 'Cara' } })
    fireEvent.change(within(form).getByLabelText('E-mail (used to sign in)'), { target: { value: 'cara@x.test' } })
    fireEvent.click(within(form).getByRole('button', { name: 'Generate strong password' }))
    const password = (within(form).getByLabelText('Password') as HTMLInputElement).value
    expect(password).toHaveLength(18)
    fireEvent.click(within(form).getByRole('button', { name: 'Create account' }))
    expect(await screen.findByText(/Account created for Cara/)).toBeInTheDocument()
    expect(JSON.parse(calls.find((c) => c.url === 'create')!.body)).toEqual({
      email: 'cara@x.test',
      display_name: 'Cara',
      role: 'analyst',
      password,
    })
    // The password is gone from the page once it was sent.
    await waitFor(() => expect((within(form).getByLabelText('Password') as HTMLInputElement).value).toBe(''))
  })

  it('asks for the admin password when granting lead, and adds a person to a case', async () => {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal('fetch', routes(['users:manage'], calls))
    renderPage()
    const form = await screen.findByRole('form', { name: 'Create account' })
    fireEvent.change(within(form).getByLabelText(/^Role/), { target: { value: 'lead' } })
    expect(within(form).getByLabelText('Your password (to confirm granting this role)')).toBeInTheDocument()

    const add = await screen.findByRole('form', { name: 'Add case member' })
    await within(add).findByRole('option', { name: 'Bob Analyst (analyst)' })
    expect(within(add).queryByRole('option', { name: /Ada Admin/ })).toBeNull() // admins see every case
    fireEvent.change(within(add).getByLabelText('Person'), { target: { value: 'u2' } })
    fireEvent.click(within(add).getByRole('button', { name: 'Add to case' }))
    await waitFor(() => expect(calls.some((c) => c.url === 'member')).toBe(true))
    expect(JSON.parse(calls.find((c) => c.url === 'member')!.body)).toEqual({ user_id: 'u2', role: 'analyst' })
  })

  it('is only for administrators', async () => {
    vi.stubGlobal('fetch', routes(['case:read']))
    renderPage()
    expect(await screen.findByText('The admin page is for administrators.')).toBeInTheDocument()
  })
})
