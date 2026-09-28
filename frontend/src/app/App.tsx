import { HealthStatus } from '@/features/health/HealthStatus'

const NAV = ['Cases', 'Evidence', 'Timeline', 'Alerts', 'Reports', 'Admin'] as const

/** Placeholder application shell (Phase 0). Real routes arrive in Phase 4. */
export function App() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <header className="border-b border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
          <h1 className="text-lg font-semibold tracking-tight">dfirbench</h1>
          <nav aria-label="Primary">
            <ul className="flex gap-4 text-sm text-slate-400">
              {NAV.map((item) => (
                <li key={item} aria-disabled="true" title="Coming in a later phase">
                  {item}
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-8">
        <section
          aria-labelledby="system-status"
          className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900"
        >
          <h2 id="system-status" className="mb-4 text-base font-semibold">
            System status
          </h2>
          <HealthStatus />
        </section>
      </main>
    </div>
  )
}
