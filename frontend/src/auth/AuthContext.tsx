import { useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

import { apiGet, apiRequest, refreshAccess, setAccessToken, setAuthLostHandler, TOKEN_DELIVERY } from '@/api/client'
import type { LoginResponse, Me, Permission, TokenResponse } from '@/api/types'

type Status = 'loading' | 'anonymous' | 'authenticated'

export interface LoginOutcome {
  mfaChallenge?: string
}

interface AuthValue {
  status: Status
  me: Me | null
  login(email: string, password: string): Promise<LoginOutcome>
  verifyMfa(challenge: string, code: { code?: string; recovery_code?: string }): Promise<void>
  logout(): Promise<void>
  can(permission: Permission): boolean
}

const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<Status>('loading')
  const [me, setMe] = useState<Me | null>(null)

  const clear = useCallback(() => {
    setAccessToken(null)
    setMe(null)
    setStatus('anonymous')
    queryClient.clear()
  }, [queryClient])

  const loadMe = useCallback(async () => {
    const data = await apiGet<Me>('/me')
    setMe(data)
    setStatus('authenticated')
  }, [])

  useEffect(() => {
    setAuthLostHandler(clear)
    let cancelled = false
    // Resume a session from the HttpOnly refresh cookie (nothing is stored in JS storage).
    refreshAccess()
      .then(async (ok) => {
        if (cancelled) return
        if (ok) await loadMe()
        else setStatus('anonymous')
      })
      .catch(() => {
        if (!cancelled) clear()
      })
    return () => {
      cancelled = true
      setAuthLostHandler(null)
    }
  }, [clear, loadMe])

  const accept = useCallback(
    async (tokens: TokenResponse) => {
      setAccessToken(tokens.access_token)
      await loadMe()
    },
    [loadMe],
  )

  const login = useCallback(
    async (email: string, password: string): Promise<LoginOutcome> => {
      const res = await apiRequest<LoginResponse>('POST', '/auth/login', {
        body: { email, password },
        headers: { ...TOKEN_DELIVERY },
      })
      if (res.mfa_required && res.mfa_challenge) return { mfaChallenge: res.mfa_challenge }
      if (!res.tokens) throw new Error('Login failed.')
      await accept(res.tokens)
      return {}
    },
    [accept],
  )

  const verifyMfa = useCallback(
    async (challenge: string, code: { code?: string; recovery_code?: string }) => {
      const tokens = await apiRequest<TokenResponse>('POST', '/auth/mfa/verify', {
        body: { mfa_challenge: challenge, ...code },
        headers: { ...TOKEN_DELIVERY },
      })
      await accept(tokens)
    },
    [accept],
  )

  const logout = useCallback(async () => {
    try {
      await apiRequest<void>('POST', '/auth/logout', { headers: { ...TOKEN_DELIVERY } })
    } catch {
      // The local session is cleared regardless; the server revokes on its side.
    } finally {
      clear()
    }
  }, [clear])

  const value = useMemo<AuthValue>(
    () => ({
      status,
      me,
      login,
      verifyMfa,
      logout,
      can: (p: Permission) => me?.permissions.includes(p) ?? false,
    }),
    [status, me, login, verifyMfa, logout],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth outside AuthProvider')
  return value
}
