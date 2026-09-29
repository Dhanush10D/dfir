import { apiGet, setAccessToken, setAuthLostHandler } from './client'
import { jsonResponse } from '@/test/utils'

function headersOf(init: RequestInit | undefined): Record<string, string> {
  return (init?.headers ?? {}) as Record<string, string>
}

afterEach(() => {
  setAccessToken(null)
  setAuthLostHandler(null)
})

describe('401 -> refresh -> retry exactly once', () => {
  it('refreshes once, retries with the new token and returns the result', async () => {
    setAccessToken('old')
    let dataCalls = 0
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === '/api/v1/auth/refresh') {
        expect(headersOf(init)['X-Token-Delivery']).toBe('cookie')
        expect(init?.credentials).toBe('same-origin')
        return jsonResponse(200, { access_token: 'new' })
      }
      dataCalls += 1
      return headersOf(init).Authorization === 'Bearer new'
        ? jsonResponse(200, { ok: true })
        : jsonResponse(401, { error: { code: 'token_expired', message: 'expired', details: {}, request_id: null } })
    })
    vi.stubGlobal('fetch', fetchMock)
    await expect(apiGet('/data')).resolves.toEqual({ ok: true })
    expect(dataCalls).toBe(2)
    expect(fetchMock.mock.calls.filter(([u]) => u === '/api/v1/auth/refresh')).toHaveLength(1)
  })

  it('shares one refresh between concurrent 401s (no token-reuse alarms)', async () => {
    setAccessToken('old')
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url === '/api/v1/auth/refresh') {
        await new Promise((r) => setTimeout(r, 10))
        return jsonResponse(200, { access_token: 'new' })
      }
      return headersOf(init).Authorization === 'Bearer new'
        ? jsonResponse(200, { url })
        : jsonResponse(401, { error: { code: 'token_expired', message: 'expired', details: {}, request_id: null } })
    })
    vi.stubGlobal('fetch', fetchMock)
    const results = await Promise.all([apiGet('/a'), apiGet('/b'), apiGet('/c')])
    expect(results).toHaveLength(3)
    expect(fetchMock.mock.calls.filter(([u]) => u === '/api/v1/auth/refresh')).toHaveLength(1)
  })

  it('logs out when the refresh fails and never retries', async () => {
    setAccessToken('old')
    const lost = vi.fn()
    setAuthLostHandler(lost)
    const fetchMock = vi.fn(async (url: string) =>
      url === '/api/v1/auth/refresh'
        ? jsonResponse(401, { error: { code: 'refresh_reused', message: 'reused', details: {}, request_id: null } })
        : jsonResponse(401, { error: { code: 'token_expired', message: 'expired', details: {}, request_id: null } }),
    )
    vi.stubGlobal('fetch', fetchMock)
    await expect(apiGet('/data')).rejects.toMatchObject({ status: 401 })
    expect(lost).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls.filter(([u]) => u === '/api/v1/data')).toHaveLength(1)
  })

  it('retries only once: a second 401 after refresh ends the session', async () => {
    setAccessToken('old')
    const lost = vi.fn()
    setAuthLostHandler(lost)
    const fetchMock = vi.fn(async (url: string) =>
      url === '/api/v1/auth/refresh'
        ? jsonResponse(200, { access_token: 'new' })
        : jsonResponse(401, { error: { code: 'token_invalid', message: 'no', details: {}, request_id: null } }),
    )
    vi.stubGlobal('fetch', fetchMock)
    await expect(apiGet('/data')).rejects.toMatchObject({ status: 401 })
    expect(fetchMock.mock.calls.filter(([u]) => u === '/api/v1/data')).toHaveLength(2)
    expect(lost).toHaveBeenCalledTimes(1)
  })
})
