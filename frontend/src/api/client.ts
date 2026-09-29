/**
 * Typed fetch wrapper: the one place that handles auth and error mapping (guide 17.4).
 *
 * Token handling: the short-lived access token lives only in this module's memory (never in
 * localStorage/sessionStorage). The refresh token is an HttpOnly, SameSite=Strict cookie scoped to
 * /api/v1/auth that JavaScript cannot read; `X-Token-Delivery: cookie` asks the API to use it.
 * A 401 triggers one single-flight refresh and exactly one retry; if that fails the auth-lost
 * handler logs the user out.
 */

export const API_BASE = '/api/v1'
export const TOKEN_DELIVERY = { 'X-Token-Delivery': 'cookie' } as const

export interface ErrorEnvelope {
  error: {
    code: string
    message: string
    details: Record<string, unknown>
    request_id: string | null
  }
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details: Record<string, unknown>
  readonly requestId: string | null

  constructor(
    status: number,
    code: string,
    message: string,
    details: Record<string, unknown> = {},
    requestId: string | null = null,
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.details = details
    this.requestId = requestId
  }
}

function isErrorEnvelope(value: unknown): value is ErrorEnvelope {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false
  const err = (value as { error: unknown }).error
  return typeof err === 'object' && err !== null && 'code' in err && 'message' in err
}

let accessToken: string | null = null
let refreshing: Promise<boolean> | null = null
let authLost: (() => void) | null = null

export function setAccessToken(token: string | null): void {
  accessToken = token
}

export function hasAccessToken(): boolean {
  return accessToken !== null
}

export function setAuthLostHandler(handler: (() => void) | null): void {
  authLost = handler
}

async function doRefresh(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: 'POST',
      headers: { Accept: 'application/json', ...TOKEN_DELIVERY },
      credentials: 'same-origin',
    })
    if (!res.ok) {
      accessToken = null
      return false
    }
    const body = (await res.json()) as { access_token?: unknown }
    if (typeof body.access_token !== 'string') {
      accessToken = null
      return false
    }
    accessToken = body.access_token
    return true
  } catch {
    accessToken = null
    return false
  }
}

/**
 * Exchange the refresh cookie for a new access token. Concurrent callers share one request
 * (a second refresh with the already-rotated cookie would look like token theft to the server);
 * across tabs the Web Locks API serialises refreshes where available.
 */
export function refreshAccess(): Promise<boolean> {
  if (!refreshing) {
    const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined
    const run = locks ? locks.request('dfirbench-refresh', () => doRefresh()) : doRefresh()
    refreshing = run.finally(() => {
      refreshing = null
    })
  }
  return refreshing
}

async function parse<T>(res: Response): Promise<T> {
  if (res.status === 204) return undefined as T
  const body: unknown = await res.json().catch(() => null)
  if (!res.ok) {
    if (isErrorEnvelope(body)) {
      const { code, message, details, request_id } = body.error
      throw new ApiError(res.status, code, message, details, request_id)
    }
    throw new ApiError(res.status, 'http_error', `HTTP ${res.status}`)
  }
  return body as T
}

export interface RequestOptions {
  body?: unknown
  /** Sent as-is (e.g. a File for a streaming upload) instead of a JSON body. */
  rawBody?: Blob
  signal?: AbortSignal
  headers?: Record<string, string>
}

async function send(method: string, path: string, opts: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json', ...opts.headers }
  if (opts.body !== undefined && opts.rawBody === undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`
  const body = opts.rawBody ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body))
  return fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body,
    credentials: 'same-origin',
    signal: opts.signal,
  })
}

/** Send a request; on 401 refresh once and retry exactly once. Returns the raw response. */
export async function apiFetch(
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<Response> {
  let res = await send(method, path, opts)
  if (res.status === 401 && !path.startsWith('/auth/')) {
    const refreshed = await refreshAccess()
    if (!refreshed) {
      authLost?.()
      return res
    }
    res = await send(method, path, opts)
    if (res.status === 401) authLost?.()
  }
  return res
}

export async function apiRequest<T>(
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<T> {
  return parse<T>(await apiFetch(method, path, opts))
}

export function apiGet<T>(path: string, init?: { signal?: AbortSignal | null }): Promise<T> {
  return apiRequest<T>('GET', path, { signal: init?.signal ?? undefined })
}

export function apiPost<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  return apiRequest<T>('POST', path, { body, signal })
}
