import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '@/api/endpoints'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

import { EntityGraph } from './EntityGraph'

const TYPES = ['', 'host', 'user', 'ip', 'process', 'hash']

function EntityDetailPane({ id, onSelect }: { id: string; onSelect: (id: string) => void }) {
  const { caseId } = useCase()
  const detail = useQuery({ queryKey: ['entity', id], queryFn: ({ signal }) => api.entity(id, signal) })
  if (detail.isPending) return <Loading />
  if (detail.error) return <ErrorMessage error={detail.error} />
  const e = detail.data
  return (
    <div className="space-y-2 text-sm">
      <h3 className="font-semibold break-all">
        {e.type}: {e.canonical}
      </h3>
      <p className="text-xs text-slate-500">
        {e.event_count} events · {formatUtc(e.first_seen)} → {formatUtc(e.last_seen)} · {e.alert_count} alerts
      </p>
      {e.pivot_query && (
        <Link to={caseHref(caseId, 'timeline', { q: e.pivot_query })} className="text-sky-700 hover:underline dark:text-sky-400">
          Open in timeline
        </Link>
      )}
      <h4 className="font-medium">Aliases</h4>
      <ul className="text-xs">
        {e.aliases.map((a) => (
          <li key={`${a.alias_type}:${a.alias}`} className="break-all">
            <span className="text-slate-500">{a.alias_type}</span> {a.alias}
          </li>
        ))}
      </ul>
      <h4 className="font-medium">Neighbours</h4>
      <ul className="text-xs">
        {e.neighbours.map((n) => (
          <li key={`${n.entity.id}-${n.relation}-${n.direction}`}>
            {n.direction === 'out' ? '→' : '←'} {n.relation}{' '}
            <button type="button" className="text-sky-700 hover:underline dark:text-sky-400" onClick={() => onSelect(n.entity.id)}>
              {n.entity.type} {n.entity.canonical}
            </button>{' '}
            ({n.weight})
          </li>
        ))}
      </ul>
    </div>
  )
}

export function EntitiesTab() {
  const { caseId } = useCase()
  const [type, setType] = useState('')
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const list = useQuery({
    queryKey: ['entities', caseId, type, q],
    queryFn: ({ signal }) => api.entities(caseId, type, q, signal),
  })
  const graph = useQuery({
    queryKey: ['graph', caseId, selected],
    queryFn: ({ signal }) => api.graph(caseId, selected, signal),
  })
  return (
    <div className="grid gap-3 xl:grid-cols-[22rem_1fr]">
      <Panel title="Entities">
        <div className="mb-2 flex gap-2">
          <label className="text-sm">
            <span className="sr-only">Type</span>
            <select className={inputClass} value={type} onChange={(e) => setType(e.target.value)} aria-label="Entity type">
              {TYPES.map((t) => (
                <option key={t} value={t}>
                  {t || 'all types'}
                </option>
              ))}
            </select>
          </label>
          <label className="flex-1 text-sm">
            <span className="sr-only">Search entities</span>
            <input className={`${inputClass} w-full`} placeholder="search name or alias" value={q} maxLength={200} onChange={(e) => setQ(e.target.value)} />
          </label>
        </div>
        {list.isPending && <Loading />}
        <ErrorMessage error={list.error} />
        <ul className="max-h-[32rem] overflow-y-auto text-sm">
          {list.data?.items.map((e) => (
            <li key={e.id}>
              <button
                type="button"
                aria-pressed={selected === e.id}
                onClick={() => setSelected(e.id)}
                className={`w-full truncate px-1 py-1 text-left hover:bg-sky-50 dark:hover:bg-slate-800 ${selected === e.id ? 'bg-sky-100 dark:bg-slate-700' : ''}`}
              >
                <span className="text-xs text-slate-500">{e.type}</span> {e.canonical}{' '}
                <span className="text-xs text-slate-500">({e.event_count})</span>
              </button>
            </li>
          ))}
        </ul>
      </Panel>
      <div className="space-y-3">
        <Panel title="Graph">
          {graph.isPending && <Loading />}
          <ErrorMessage error={graph.error} />
          {graph.data && <EntityGraph graph={graph.data} focusId={selected} onSelect={setSelected} />}
        </Panel>
        {selected && (
          <Panel title="Entity detail">
            <EntityDetailPane id={selected} onSelect={setSelected} />
          </Panel>
        )}
      </div>
    </div>
  )
}
