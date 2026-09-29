import type { KeyboardEvent } from 'react'

import type { Graph } from '@/api/types'

const COLORS: Record<string, string> = {
  host: 'fill-sky-600',
  user: 'fill-emerald-600',
  ip: 'fill-amber-600',
  process: 'fill-violet-600',
  hash: 'fill-slate-600',
}
const SIZE = 520

/**
 * Deterministic radial layout (no physics, no dependency): the focus entity in the middle,
 * everything else on rings grouped by type. Nodes are focusable buttons; an edge table below the
 * picture gives the same information to screen readers.
 */
export function EntityGraph({
  graph,
  focusId,
  onSelect,
}: {
  graph: Graph
  focusId: string | null
  onSelect: (id: string) => void
}) {
  const center = SIZE / 2
  const others = graph.nodes.filter((n) => n.id !== focusId)
  others.sort((a, b) => a.type.localeCompare(b.type) || a.canonical.localeCompare(b.canonical))
  const pos = new Map<string, { x: number; y: number }>()
  if (focusId) pos.set(focusId, { x: center, y: center })
  const ringSize = 24
  others.forEach((n, i) => {
    const ring = Math.floor(i / ringSize)
    const inRing = Math.min(ringSize, others.length - ring * ringSize)
    const angle = ((i % ringSize) / inRing) * 2 * Math.PI + ring * 0.3
    const r = 110 + ring * 70
    pos.set(n.id, { x: center + r * Math.cos(angle), y: center + r * Math.sin(angle) })
  })
  const name = new Map(graph.nodes.map((n) => [n.id, `${n.type} ${n.canonical}`]))

  function key(e: KeyboardEvent<SVGGElement>, id: string) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect(id)
    }
  }

  return (
    <div>
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="h-auto w-full max-w-2xl" role="group" aria-label="Entity graph">
        {graph.edges.map((e) => {
          const a = pos.get(e.src_entity)
          const b = pos.get(e.dst_entity)
          if (!a || !b) return null
          return (
            <line
              key={`${e.src_entity}-${e.dst_entity}-${e.relation}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              className="stroke-slate-300 dark:stroke-slate-600"
              strokeWidth={Math.min(1 + Math.log10(e.weight + 1), 4)}
            />
          )
        })}
        {graph.nodes.map((n) => {
          const p = pos.get(n.id)
          if (!p) return null
          const label = n.canonical.length > 22 ? `${n.canonical.slice(0, 21)}…` : n.canonical
          return (
            <g
              key={n.id}
              role="button"
              tabIndex={0}
              aria-label={`${n.type} ${n.canonical}`}
              onClick={() => onSelect(n.id)}
              onKeyDown={(e) => key(e, n.id)}
              className="cursor-pointer focus:outline-none [&:focus>circle]:stroke-sky-400 [&:focus>circle]:stroke-4"
            >
              <circle cx={p.x} cy={p.y} r={n.id === focusId ? 12 : 8} className={COLORS[n.type] ?? 'fill-slate-500'} />
              <text x={p.x} y={p.y + 20} textAnchor="middle" className="fill-slate-700 text-[9px] dark:fill-slate-200">
                {label}
              </text>
            </g>
          )
        })}
      </svg>
      {graph.truncated && <p className="text-xs text-amber-700">Graph truncated at the node/edge cap.</p>}
      <details className="mt-2 text-sm">
        <summary>Edges ({graph.edges.length})</summary>
        <table className="w-full text-left text-xs">
          <caption className="sr-only">Graph edges</caption>
          <thead>
            <tr>
              <th scope="col">From</th>
              <th scope="col">Relation</th>
              <th scope="col">To</th>
              <th scope="col">Count</th>
            </tr>
          </thead>
          <tbody>
            {graph.edges.map((e) => (
              <tr key={`${e.src_entity}-${e.dst_entity}-${e.relation}`}>
                <td className="break-all">{name.get(e.src_entity)}</td>
                <td>{e.relation}</td>
                <td className="break-all">{name.get(e.dst_entity)}</td>
                <td>{e.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}
