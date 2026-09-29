import { useQuery } from '@tanstack/react-query'

import { api } from '@/api/endpoints'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { ErrorMessage, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'
import { quoteValue } from '@/lib/searchLanguage'

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded border border-slate-200 p-3 dark:border-slate-700">
      <dt className="text-xs text-slate-500 uppercase">{label}</dt>
      <dd className="text-xl font-semibold">{value}</dd>
    </div>
  )
}

export function Overview() {
  const { caseId, detail } = useCase()
  const q = useQuery({ queryKey: ['summary', caseId], queryFn: ({ signal }) => api.summary(caseId, signal) })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const s = q.data
  const pivot = (field: string, value: string) => caseHref(caseId, 'timeline', { q: `${field}:${quoteValue(value)}` })
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Case">
        {detail.description && <p className="mb-3 text-sm whitespace-pre-wrap">{detail.description}</p>}
        <dl className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          <Stat label="Risk" value={s.risk.case_risk} />
          <Stat label="Events" value={s.events} />
          <Stat label="Evidence" value={s.evidence} />
          <Stat label="Entities" value={s.entities} />
          <Stat label="Notes" value={s.notes} />
          <Stat label="Active jobs" value={s.jobs_active} />
        </dl>
        <p className="mt-3 text-xs text-slate-500">
          Timeline span: {formatUtc(s.first_event)} → {formatUtc(s.last_event)}
        </p>
      </Panel>
      <Panel title="Alerts">
        <h3 className="text-sm font-medium">By severity</h3>
        <ul className="mb-2 text-sm">
          {Object.entries(s.alerts_by_severity).map(([k, v]) => (
            <li key={k}>
              {k}: {v}
            </li>
          ))}
        </ul>
        <h3 className="text-sm font-medium">By status</h3>
        <ul className="text-sm">
          {Object.entries(s.alerts_by_status).map(([k, v]) => (
            <li key={k}>
              {k}: {v}
            </li>
          ))}
        </ul>
        {s.risk.tactics.length > 0 && (
          <p className="mt-2 text-xs text-slate-500">Tactics: {s.risk.tactics.join(', ')}</p>
        )}
      </Panel>
      {(['top_hosts', 'top_users'] as const).map((key) => (
        <Panel key={key} title={key === 'top_hosts' ? 'Top hosts' : 'Top users'}>
          <ul className="text-sm">
            {s[key].map((v) => (
              <li key={v.value} className="flex justify-between gap-2">
                <Link to={pivot(key === 'top_hosts' ? 'host' : 'user', v.value)} className="truncate text-sky-700 hover:underline dark:text-sky-400">
                  {v.value}
                </Link>
                <span className="text-slate-500">{v.count}</span>
              </li>
            ))}
          </ul>
        </Panel>
      ))}
    </div>
  )
}
