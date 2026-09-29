import { useState, type FormEvent } from 'react'

import { useAuth } from '@/auth/AuthContext'
import { Button, ErrorMessage, inputClass } from '@/components/ui'

/** Password login, then TOTP (or a recovery code) when the account has MFA (guide 16.2). */
export function LoginPage() {
  const { login, verifyMfa } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [useRecovery, setUseRecovery] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  async function submitPassword(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const out = await login(email, password)
      setPassword('')
      if (out.mfaChallenge) setChallenge(out.mfaChallenge)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault()
    if (!challenge) return
    setBusy(true)
    setError(null)
    try {
      await verifyMfa(challenge, useRecovery ? { recovery_code: code.trim() } : { code: code.trim() })
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="flex min-h-screen items-start justify-center bg-slate-50 px-4 pt-24 dark:bg-slate-950">
      <div className="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h1 className="mb-4 text-lg font-semibold">dfirbench sign in</h1>
        {challenge === null ? (
          <form onSubmit={submitPassword} className="space-y-3" aria-label="Sign in">
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Email</span>
              <input
                className={`${inputClass} w-full`}
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Password</span>
              <input
                className={`${inputClass} w-full`}
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <ErrorMessage error={error} />
            <Button type="submit" variant="primary" disabled={busy} className="w-full">
              {busy ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        ) : (
          <form onSubmit={submitCode} className="space-y-3" aria-label="Two-factor authentication">
            <label className="block text-sm">
              <span className="mb-1 block font-medium">
                {useRecovery ? 'Recovery code' : 'Authenticator code'}
              </span>
              <input
                className={`${inputClass} w-full font-mono`}
                autoComplete="one-time-code"
                inputMode={useRecovery ? 'text' : 'numeric'}
                maxLength={useRecovery ? 32 : 8}
                required
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </label>
            <ErrorMessage error={error} />
            <Button type="submit" variant="primary" disabled={busy} className="w-full">
              Verify
            </Button>
            <Button variant="ghost" onClick={() => setUseRecovery((v) => !v)}>
              {useRecovery ? 'Use an authenticator code' : 'Use a recovery code'}
            </Button>
          </form>
        )}
      </div>
    </main>
  )
}
