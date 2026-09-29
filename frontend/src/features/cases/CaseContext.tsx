import { createContext, useContext } from 'react'

import type { CaseDetail, Permission } from '@/api/types'

export interface CaseCtx {
  caseId: string
  detail: CaseDetail
  userId: string
  /** Effective permissions on this case (server-computed). The server still enforces them. */
  can(permission: Permission): boolean
  closed: boolean
}

export const CaseContext = createContext<CaseCtx | null>(null)

export function useCase(): CaseCtx {
  const value = useContext(CaseContext)
  if (!value) throw new Error('useCase outside CaseContext')
  return value
}

export function makeCaseCtx(detail: CaseDetail, userId: string): CaseCtx {
  const perms = new Set(detail.my_permissions)
  const closed = detail.status === 'closed'
  return {
    caseId: detail.id,
    detail,
    userId,
    closed,
    // Closed cases are read-only: hide write actions (the API answers 409 anyway).
    can: (p) => perms.has(p) && (!closed || p === 'case:read' || p === 'custody:view'),
  }
}
