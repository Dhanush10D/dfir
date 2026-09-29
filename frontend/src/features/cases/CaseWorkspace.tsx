import { useQuery } from '@tanstack/react-query'
import { useMemo, type ComponentType } from 'react'

import { api } from '@/api/endpoints'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { useAuth } from '@/auth/AuthContext'
import { ErrorMessage, Loading, SeverityChip } from '@/components/ui'
import { AlertsTab } from '@/features/alerts/AlertsTab'
import { AttackMatrix } from '@/features/attack/AttackMatrix'
import { EntitiesTab } from '@/features/entities/EntitiesTab'
import { EvidenceTab } from '@/features/evidence/EvidenceTab'
import { Explorer } from '@/features/explorer/Explorer'
import { NotesTab } from '@/features/notes/NotesTab'
import { Overview } from '@/features/overview/Overview'
import { ProcessTreeTab } from '@/features/proctree/ProcessTreeTab'

import { CaseContext, makeCaseCtx } from './CaseContext'

const TABS: { id: string; label: string; component: ComponentType }[] = [
  { id: 'overview', label: 'Overview', component: Overview },
  { id: 'evidence', label: 'Evidence & custody', component: EvidenceTab },
  { id: 'timeline', label: 'Timeline', component: Explorer },
  { id: 'alerts', label: 'Alerts', component: AlertsTab },
  { id: 'attack', label: 'ATT&CK', component: AttackMatrix },
  { id: 'entities', label: 'Entities & graph', component: EntitiesTab },
  { id: 'process', label: 'Process tree', component: ProcessTreeTab },
  { id: 'notes', label: 'Notes & bookmarks', component: NotesTab },
]

export function CaseWorkspace({ id, tab }: { id: string; tab: string }) {
  const { me } = useAuth()
  const detail = useQuery({ queryKey: ['case', id], queryFn: ({ signal }) => api.caseDetail(id, signal) })
  const ctx = useMemo(
    () => (detail.data && me ? makeCaseCtx(detail.data, me.user.id) : null),
    [detail.data, me],
  )
  if (detail.isPending) return <Loading />
  if (detail.error || !ctx) return <ErrorMessage error={detail.error ?? new Error('Case unavailable')} />
  const active = TABS.find((t) => t.id === tab) ?? TABS[0]
  const Active = active!.component
  const c = ctx.detail
  return (
    <CaseContext.Provider value={ctx}>
      <div className="space-y-3">
        <header className="flex flex-wrap items-center gap-3">
          <h1 className="text-lg font-semibold">
            <span className="font-mono">{c.case_number}</span> {c.title}
          </h1>
          <SeverityChip severity={c.severity} />
          <span className="rounded bg-slate-200 px-1.5 py-0.5 text-xs dark:bg-slate-700">Status: {c.status}</span>
          {ctx.closed && <span className="text-xs text-slate-500">(closed: read-only)</span>}
        </header>
        <nav aria-label="Case sections">
          <ul className="flex flex-wrap gap-1 border-b border-slate-200 dark:border-slate-800">
            {TABS.map((t) => (
              <li key={t.id}>
                <Link
                  to={caseHref(id, t.id)}
                  aria-current={t.id === active!.id ? 'page' : undefined}
                  className={`block rounded-t px-3 py-1.5 text-sm ${
                    t.id === active!.id
                      ? 'border border-b-0 border-slate-200 bg-white font-semibold dark:border-slate-700 dark:bg-slate-900'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400'
                  }`}
                >
                  {t.label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
        <Active />
      </div>
    </CaseContext.Provider>
  )
}
