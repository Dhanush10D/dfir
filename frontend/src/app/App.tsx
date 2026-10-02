import { useEffect } from 'react'

import { useAuth } from '@/auth/AuthContext'
import { Button, Loading } from '@/components/ui'
import { CaseList } from '@/features/cases/CaseList'
import { CaseWorkspace } from '@/features/cases/CaseWorkspace'
import { HealthStatus } from '@/features/health/HealthStatus'
import { IntegrationsPage } from '@/features/integrations/IntegrationsPage'
import { NotificationsPage } from '@/features/integrations/NotificationsPage'
import { LoginPage } from '@/features/login/LoginPage'

import { Link } from './Link'
import { matchRoute, navigate, useLocation } from './router'

/** Application shell: session gate, header, and the routed page. */
export function App() {
  const { status, me, logout, can } = useAuth()
  const { path } = useLocation()
  const route = matchRoute(path)

  useEffect(() => {
    // Keep protected URLs shareable without rendering their contents before authentication
    // finishes restoring, and send an already-authenticated user away from the login screen.
    if (status === 'anonymous' && route.name !== 'login') navigate('/login', { replace: true })
    if (status === 'authenticated' && route.name === 'login') navigate('/cases', { replace: true })
  }, [status, route.name])

  if (status === 'loading') {
    return (
      <main className="p-8">
        <Loading label="Restoring session…" />
      </main>
    )
  }
  if (status === 'anonymous') return <LoginPage />

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-screen-2xl flex-wrap items-center justify-between gap-2 px-4 py-2">
          <div className="flex items-center gap-4">
            <Link to="/cases" className="text-lg font-semibold tracking-tight">
              dfirbench
            </Link>
            <nav aria-label="Primary" className="flex items-center gap-3">
              <Link to="/cases" className="text-sm text-slate-600 hover:text-slate-900 dark:text-slate-300">
                Cases
              </Link>
              <Link to="/notifications" className="text-sm text-slate-600 hover:text-slate-900 dark:text-slate-300">
                Notifications
              </Link>
              {can('users:manage') && (
                <Link to="/integrations" className="text-sm text-slate-600 hover:text-slate-900 dark:text-slate-300">
                  Integrations
                </Link>
              )}
            </nav>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span>
              {me?.user.display_name} <span className="text-slate-500">({me?.user.role})</span>
            </span>
            <Button onClick={() => void logout()}>Sign out</Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-screen-2xl px-4 py-4">
        {route.name === 'case' ? (
          <CaseWorkspace key={route.id} id={route.id} tab={route.tab} />
        ) : route.name === 'integrations' ? (
          <IntegrationsPage />
        ) : route.name === 'notifications' ? (
          <NotificationsPage />
        ) : route.name === 'notfound' ? (
          <p>Page not found.</p>
        ) : (
          <CaseList />
        )}
      </main>
      <footer className="mx-auto max-w-screen-2xl px-4 pb-4">
        <details className="text-xs text-slate-500">
          <summary>System status</summary>
          <HealthStatus />
        </details>
      </footer>
    </div>
  )
}
