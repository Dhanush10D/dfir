import { QueryClient } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import { ApiError, apiGet, setAccessToken } from '@/api/client'
import { AuthProvider } from '@/auth/AuthContext'
import { jsonResponse, routeFetch } from '@/test/utils'

import { App } from './App'
import { Providers } from './providers'

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Providers client={client}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </Providers>,
  )
}

const ME = {
  user: { id: 'u1', email: 'a@x.test', display_name: 'Ana Analyst', role: 'analyst', mfa_enabled: true },
  permissions: ['case:read', 'investigate'],
  auth_method: 'jwt',
}
const TOKENS = {
  access_token: 'access-1',
  token_type: 'bearer',
  expires_at: '2026-09-14T08:15:00Z',
  refresh_token: null,
  refresh_expires_at: '2026-09-21T08:00:00Z',
}

beforeEach(() => {
  setAccessToken(null)
  window.history.replaceState(null, '', '/')
})

describe('App shell and login', () => {
  it('shows the sign-in page when the refresh cookie does not resume a session', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({ 'POST /api/v1/auth/refresh': () => jsonResponse(401, { error: { code: 'token_invalid', message: 'x', details: {}, request_id: null } }) }),
    )
    renderApp()
    expect(await screen.findByRole('heading', { name: 'dfirbench sign in' })).toBeInTheDocument()
    await waitFor(() => expect(window.location.pathname).toBe('/login'))
  })

  it('signs in with password + TOTP, keeps tokens out of web storage', async () => {
    const fetchMock = routeFetch({
      'POST /api/v1/auth/refresh': () => jsonResponse(401, { error: { code: 'token_invalid', message: 'x', details: {}, request_id: null } }),
      'POST /api/v1/auth/login': () =>
        jsonResponse(200, { mfa_required: true, mfa_challenge: 'challenge-123456', mfa_expires_at: null, tokens: null }),
      'POST /api/v1/auth/mfa/verify': () => jsonResponse(200, TOKENS),
      'GET /api/v1/me': () => jsonResponse(200, ME),
      'GET /api/v1/cases': () => jsonResponse(200, { items: [], total: 0 }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderApp()
    fireEvent.change(await screen.findByLabelText('Email'), { target: { value: 'a@x.test' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    fireEvent.change(await screen.findByLabelText('Authenticator code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }))
    expect(await screen.findByText('Ana Analyst')).toBeInTheDocument()

    const login = fetchMock.mock.calls.find(([url]) => url === '/api/v1/auth/login')
    expect(login?.[1]?.headers).toMatchObject({ 'X-Token-Delivery': 'cookie' })
    const verify = fetchMock.mock.calls.find(([url]) => url === '/api/v1/auth/mfa/verify')
    expect(JSON.parse(String(verify?.[1]?.body))).toMatchObject({ mfa_challenge: 'challenge-123456', code: '123456' })
    const me = fetchMock.mock.calls.find(([url]) => url === '/api/v1/me')
    expect(me?.[1]?.headers).toMatchObject({ Authorization: 'Bearer access-1' })
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
  })

  it('logout clears the session and returns to sign-in', async () => {
    const fetchMock = routeFetch({
      'POST /api/v1/auth/refresh': () => jsonResponse(200, TOKENS),
      'GET /api/v1/me': () => jsonResponse(200, ME),
      'GET /api/v1/cases': () => jsonResponse(200, { items: [], total: 0 }),
      'POST /api/v1/auth/logout': () => new Response(null, { status: 204 }),
    })
    vi.stubGlobal('fetch', fetchMock)
    renderApp()
    fireEvent.click(await screen.findByRole('button', { name: 'Sign out' }))
    expect(await screen.findByRole('heading', { name: 'dfirbench sign in' })).toBeInTheDocument()
    const logout = fetchMock.mock.calls.find(([url]) => url === '/api/v1/auth/logout')
    expect(logout?.[1]?.headers).toMatchObject({ 'X-Token-Delivery': 'cookie' })
  })
})

describe('apiGet', () => {
  it('maps the error envelope to ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () =>
        jsonResponse(404, { error: { code: 'not_found', message: 'Nope', details: { a: 1 }, request_id: 'rid' } }),
      ),
    )
    const err = await apiGet('/x').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 404, code: 'not_found', message: 'Nope', requestId: 'rid', details: { a: 1 } })
  })

  it('handles non-JSON error bodies', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response('bad gateway', { status: 502 })))
    await expect(apiGet('/x')).rejects.toMatchObject({ status: 502, code: 'http_error' })
  })
})
