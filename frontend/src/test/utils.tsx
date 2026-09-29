import { QueryClient } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { ReactElement } from 'react'

import type { CaseDetail, Permission } from '@/api/types'
import { Providers } from '@/app/providers'
import { CaseContext, makeCaseCtx } from '@/features/cases/CaseContext'

export const CASE_ID = '11111111-2222-3333-4444-555555555555'
export const USER_ID = '99999999-8888-7777-6666-555555555555'

export function jsonResponse(status: number, body: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

export function caseDetail(perms: Permission[], status = 'open'): CaseDetail {
  return {
    id: CASE_ID,
    case_number: 'IR-2026-0001',
    title: 'Test case',
    description: null,
    status,
    severity: 'medium',
    classification: null,
    opened_at: '2026-09-14T08:00:00Z',
    closed_at: null,
    my_case_role: null,
    my_permissions: perms,
  }
}

export const VIEWER: Permission[] = ['case:read']
export const ANALYST: Permission[] = [
  'case:read',
  'case:update',
  'evidence:add',
  'evidence:verify',
  'custody:view',
  'investigate',
  'alert:update',
  'ai:use',
]

export function renderInCase(ui: ReactElement, perms: Permission[], status = 'open') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <Providers client={client}>
      <CaseContext.Provider value={makeCaseCtx(caseDetail(perms, status), USER_ID)}>{ui}</CaseContext.Provider>
    </Providers>,
  )
}

/** fetch mock routing on "METHOD /path" prefixes; unknown routes answer 404. */
export function routeFetch(routes: Record<string, (init: RequestInit) => Response>) {
  return vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const key = `${(init.method ?? 'GET').toUpperCase()} ${url}`
    const match = Object.keys(routes)
      .filter((k) => key.startsWith(k))
      .sort((a, b) => b.length - a.length)[0]
    if (!match) return jsonResponse(404, { error: { code: 'not_found', message: key, details: {}, request_id: null } })
    return routes[match]!(init)
  })
}
