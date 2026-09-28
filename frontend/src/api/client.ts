/**
 * Minimal typed fetch wrapper. Maps the backend error envelope (guide 15.3) to ApiError.
 * Phase 4 replaces the hand-written types with a client generated from /api/v1/openapi.json.
 */

export const API_BASE = '/api/v1'

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

export async function apiGet<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    method: 'GET',
    headers: { Accept: 'application/json', ...init?.headers },
    credentials: 'same-origin',
  })
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    if (isErrorEnvelope(body)) {
      const { code, message, details, request_id } = body.error
      throw new ApiError(response.status, code, message, details, request_id)
    }
    throw new ApiError(response.status, 'http_error', `HTTP ${response.status}`)
  }
  return body as T
}
