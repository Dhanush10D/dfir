import { useQuery } from '@tanstack/react-query'

import { api } from '@/api/endpoints'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { ErrorMessage, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'

import { groupByTactic, HEAT, TACTICS } from './attack'

/** Technique heat map by tactic; a cell opens the timeline filtered on that technique. */
export function AttackMatrix() {
  const { caseId } = useCase()
  const q = useQuery({ queryKey: ['attack', caseId], queryFn: ({ signal }) => api.attack(caseId, signal) })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const byTactic = groupByTactic(q.data)
  const max = Math.max(1, ...q.data.map((r) => r.alerts))
  const columns = [...TACTICS.filter((t) => byTactic.has(t)), ...(byTactic.has('unmapped') ? ['unmapped'] : [])]
  return (
    <Panel title="MITRE ATT&CK">
      {columns.length === 0 && <p className="text-sm text-slate-500">No techniques observed (false positives and stale alerts excluded).</p>}
      <div className="flex gap-2 overflow-x-auto">
        {columns.map((tactic) => (
          <section key={tactic} aria-label={tactic} className="min-w-40 flex-1">
            <h3 className="mb-1 text-xs font-semibold text-slate-600 uppercase dark:text-slate-300">{tactic}</h3>
            <ul className="space-y-1">
              {(byTactic.get(tactic) ?? []).map((row) => {
                const level = HEAT[Math.min(HEAT.length - 1, Math.floor((row.alerts / max) * HEAT.length))]
                return (
                  <li key={row.technique}>
                    <Link
                      to={caseHref(caseId, 'timeline', { q: `attack_tags:${row.technique}` })}
                      className={`block rounded px-2 py-1 text-sm text-slate-900 hover:ring-2 hover:ring-sky-500 ${level}`}
                      aria-label={`${row.technique}: ${row.alerts} alerts, max severity ${row.max_severity}. Open timeline`}
                    >
                      <span className="font-mono">{row.technique}</span>
                      <span className="block text-xs">
                        {row.alerts} alert{row.alerts === 1 ? '' : 's'} · {row.max_severity}
                      </span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          </section>
        ))}
      </div>
    </Panel>
  )
}
