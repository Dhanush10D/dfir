import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { api } from '@/api/endpoints'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

import { EntityGraph } from './EntityGraph'
import { typeStyle } from './entityStyle'

const TYPES = ['', 'host', 'user', 'ip', 'process', 'hash', 'domain', 'file'] // backend ENTITY_TYPES

function TypeBadge({ type }: { type: string }) {
  const s = typeStyle(type)
  return (
    <span className={`inline-flex w-16 shrink-0 items-center gap-1.5 text-xs ${s.text}`}>
      <span aria-hidden="true" className={`h-2 w-2 rounded-full ${s.dot}`} />
      {type}
    </span>
  )
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  )
}

function EntityDetailPane({ id, onSelect }: { id: string; onSelect: (id: string) => void }) {
  const { caseId } = useCase()
  const detail = useQuery({ queryKey: ['entity', id], queryFn: ({ signal }) => api.entity(id, signal) })
  if (detail.isPending) return <Loading />
  if (detail.error) return <ErrorMessage error={detail.error} />
  const e = detail.data
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-3">
        <TypeBadge type={e.type} />
        <h3 className="font-semibold break-all">{e.canonical}</h3>
        {e.pivot_query && (
          <Link
            to={caseHref(caseId, 'timeline', { q: e.pivot_query })}
            className="ml-auto text-sky-700 hover:underline dark:text-sky-400"
          >
            Open in timeline →
          </Link>
        )}
      </div>
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Events" value={e.event_count} />
        <Stat label="Alerts" value={e.alert_count} />
        <Stat label="First seen (UTC)" value={formatUtc(e.first_seen)} />
        <Stat label="Last seen (UTC)" value={formatUtc(e.last_seen)} />
      </dl>
      <div className="grid gap-4 lg:grid-cols-[1fr_2fr]">
        <section>
          <h4 className="mb-1 font-medium">Aliases ({e.aliases.length})</h4>
          {e.aliases.length === 0 ? (
            <p className="text-xs text-slate-500">None.</p>
          ) : (
            <ul className="space-y-1 text-xs">
              {e.aliases.map((a) => (
                <li key={`${a.alias_type}:${a.alias}`} className="flex gap-2 break-all">
                  <span className="w-20 shrink-0 text-slate-500">{a.alias_type}</span>
                  <span>{a.alias}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h4 className="mb-1 font-medium">Linked entities ({e.neighbours.length})</h4>
          {e.neighbours.length === 0 ? (
            <p className="text-xs text-slate-500">None.</p>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="text-slate-500 uppercase">
                <tr>
                  <th scope="col" className="py-1">Relation</th>
                  <th scope="col">Entity</th>
                  <th scope="col" className="text-right">Count</th>
                </tr>
              </thead>
              <tbody>
                {e.neighbours.map((n) => (
                  <tr key={`${n.entity.id}-${n.relation}-${n.direction}`} className="border-t border-slate-100 dark:border-slate-800">
                    <td className="py-1 font-mono">
                      {n.direction === 'out' ? '→' : '←'} {n.relation}
                    </td>
                    <td>
                      <button
                        type="button"
                        className="inline-flex items-center gap-2 text-left text-sky-700 hover:underline dark:text-sky-400"
                        onClick={() => onSelect(n.entity.id)}
                      >
                        <TypeBadge type={n.entity.type} />
                        <span className="break-all">{n.entity.canonical}</span>
                      </button>
                    </td>
                    <td className="text-right tabular-nums">{n.weight}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
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
  const items = list.data?.items ?? []
  return (
    <div className="grid gap-4 xl:grid-cols-[22rem_1fr]">
      <Panel title="Entities">
        <div className="mb-3 flex gap-2">
          <select className={inputClass} value={type} onChange={(e) => setType(e.target.value)} aria-label="Entity type">
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {t || 'all types'}
              </option>
            ))}
          </select>
          <input
            className={`${inputClass} min-w-0 flex-1`}
            aria-label="Search entities"
            placeholder="Search name or alias"
            value={q}
            maxLength={200}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        {list.isPending && <Loading />}
        <ErrorMessage error={list.error} />
        {list.data && (
          <>
            <div className="flex justify-between border-b border-slate-200 px-2 pb-1 text-xs text-slate-500 uppercase dark:border-slate-800">
              <span>
                {items.length} entit{items.length === 1 ? 'y' : 'ies'}
              </span>
              <span>Events</span>
            </div>
            <ul className="max-h-[38rem] overflow-y-auto text-sm">
              {items.map((e) => (
                <li key={e.id}>
                  <button
                    type="button"
                    aria-pressed={selected === e.id}
                    onClick={() => setSelected(e.id)}
                    className={`flex w-full items-center gap-2 rounded px-2 py-1.5 text-left hover:bg-sky-50 dark:hover:bg-slate-800 ${
                      selected === e.id ? 'bg-sky-100 dark:bg-slate-700' : ''
                    }`}
                  >
                    <TypeBadge type={e.type} />
                    <span className="min-w-0 flex-1 truncate" title={e.canonical}>
                      {e.canonical}
                    </span>
                    <span className="text-xs text-slate-500 tabular-nums">{e.event_count}</span>
                  </button>
                </li>
              ))}
              {items.length === 0 && <li className="px-2 py-2 text-slate-500">No entities match.</li>}
            </ul>
          </>
        )}
      </Panel>
      <div className="min-w-0 space-y-4">
        <Panel
          title="Graph"
          actions={
            selected && (
              <Button variant="ghost" onClick={() => setSelected(null)}>
                Show whole case
              </Button>
            )
          }
        >
          <p className="mb-3 text-xs text-slate-500">
            {selected
              ? 'Showing the selected entity and what it is linked to. '
              : 'All entities in the case, one column per type. '}
            Hover a node to highlight its links; click one to focus on it.
          </p>
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
