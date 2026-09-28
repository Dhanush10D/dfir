import { QueryClient } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'

import { ApiError, apiGet } from '@/api/client'

import { App } from './App'
import { Providers } from './providers'

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Providers client={client}>
      <App />
    </Providers>,
  )
}

// A fresh Response per call: bodies can only be read once.
function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('App shell', () => {
  it('renders the title and API health from /api/v1/health', async () => {
    const fetchMock = vi.fn().mockImplementation(async () =>
      jsonResponse(200, {
        status: 'ok',
        service: 'dfirbench-api',
        version: '0.1.0',
        env: 'test',
        time: '2026-01-01T00:00:00Z',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    renderApp()

    expect(screen.getByRole('heading', { name: 'dfirbench' })).toBeInTheDocument()
    expect(await screen.findByText('0.1.0')).toBeInTheDocument()
    expect(screen.getByLabelText('API status')).toHaveTextContent('ok')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/health',
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('shows the error message when the API is down', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () =>
        jsonResponse(503, {
          error: { code: 'not_ready', message: 'Dependencies unavailable', details: {}, request_id: 'r1' },
        }),
      ),
    )

    renderApp()

    expect(await screen.findByText(/API unreachable: Dependencies unavailable/)).toBeInTheDocument()
  })
})

describe('apiGet', () => {
  it('maps the error envelope to ApiError', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () =>
        jsonResponse(404, {
          error: { code: 'not_found', message: 'Nope', details: { a: 1 }, request_id: 'rid' },
        }),
      ),
    )
    const err = await apiGet('/x').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({
      status: 404,
      code: 'not_found',
      message: 'Nope',
      requestId: 'rid',
      details: { a: 1 },
    })
  })

  it('handles non-JSON error bodies', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => new Response('bad gateway', { status: 502 })))
    await expect(apiGet('/x')).rejects.toMatchObject({ status: 502, code: 'http_error' })
  })
})
