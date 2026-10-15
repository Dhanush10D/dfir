import { useState, type KeyboardEvent } from 'react'

import type { Graph } from '@/api/types'

import { TYPE_ORDER, typeStyle } from './entityStyle'

const COL_W = 220
const ROW_H = 28
const TOP = 44
const PAD = 24

function label(text: string) {
  return text.length > 26 ? `${text.slice(0, 25)}…` : text
}

/**
 * Deterministic column layout (no physics, no dependency): one column per entity type, nodes
 * sorted by event count, links drawn as curves behind them. Hovering or selecting a node
 * highlights its links. Nodes are focusable buttons; an edge table below the picture gives the
 * same information to screen readers.
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
  const [hover, setHover] = useState<string | null>(null)
  const active = hover ?? focusId

  const types = [...new Set(graph.nodes.map((n) => n.type))].sort((a, b) => {
    const ia = TYPE_ORDER.indexOf(a)
    const ib = TYPE_ORDER.indexOf(b)
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b)
  })
  const columns = types.map((t) =>
    graph.nodes
      .filter((n) => n.type === t)
      .sort((a, b) => Number(b.id === focusId) - Number(a.id === focusId) || b.event_count - a.event_count || a.canonical.localeCompare(b.canonical)),
  )
  const pos = new Map<string, { x: number; y: number }>()
  columns.forEach((col, c) =>
    col.forEach((n, r) => pos.set(n.id, { x: PAD + c * COL_W + 8, y: TOP + r * ROW_H + ROW_H / 2 })),
  )
  const width = PAD * 2 + Math.max(types.length, 1) * COL_W
  const height = TOP + Math.max(1, ...columns.map((c) => c.length)) * ROW_H + PAD
  const name = new Map(graph.nodes.map((n) => [n.id, `${n.type} ${n.canonical}`]))

  const linked = new Set<string>()
  if (active) {
    linked.add(active)
    for (const e of graph.edges) {
      if (e.src_entity === active) linked.add(e.dst_entity)
      if (e.dst_entity === active) linked.add(e.src_entity)
    }
  }

  function key(e: KeyboardEvent<SVGGElement>, id: string) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect(id)
    }
  }

  function path(a: { x: number; y: number }, b: { x: number; y: number }) {
    if (a.x === b.x) {
      // same column: bow out to the left so the curve does not run over the labels
      const bow = 30 + Math.abs(b.y - a.y) * 0.15
      return `M${a.x},${a.y} C${a.x - bow},${a.y} ${b.x - bow},${b.y} ${b.x},${b.y}`
    }
    const dx = (b.x - a.x) / 2
    return `M${a.x},${a.y} C${a.x + dx},${a.y} ${b.x - dx},${b.y} ${b.x},${b.y}`
  }

  return (
    <div className="space-y-3">
      <div className="max-h-[42rem] overflow-auto rounded-md border border-slate-200 dark:border-slate-800">
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="group" aria-label="Entity graph" className="mx-auto block">
          {types.map((t, c) => (
            <text
              key={t}
              x={PAD + c * COL_W}
              y={22}
              className={`fill-current text-[11px] font-semibold tracking-wide uppercase ${typeStyle(t).text}`}
            >
              {t} ({columns[c]!.length})
            </text>
          ))}
          {graph.edges.map((e) => {
            const a = pos.get(e.src_entity)
            const b = pos.get(e.dst_entity)
            if (!a || !b) return null
            const on = active !== null && (e.src_entity === active || e.dst_entity === active)
            const stroke = on
              ? 'stroke-sky-500 opacity-90'
              : `stroke-slate-400 dark:stroke-slate-500 ${active ? 'opacity-10' : 'opacity-40'}`
            return (
              <path
                key={`${e.src_entity}-${e.dst_entity}-${e.relation}`}
                d={path(a, b)}
                fill="none"
                className={stroke}
                strokeWidth={Math.min(1 + Math.log10(e.weight + 1), 4)}
              >
                <title>
                  {name.get(e.src_entity)} → {name.get(e.dst_entity)}: {e.relation} ({e.weight})
                </title>
              </path>
            )
          })}
          {graph.nodes.map((n) => {
            const p = pos.get(n.id)
            if (!p) return null
            const dim = active !== null && !linked.has(n.id)
            const isFocus = n.id === focusId
            return (
              <g
                key={n.id}
                role="button"
                tabIndex={0}
                aria-label={`${n.type} ${n.canonical}`}
                aria-pressed={isFocus}
                onClick={() => onSelect(n.id)}
                onKeyDown={(e) => key(e, n.id)}
                onMouseEnter={() => setHover(n.id)}
                onMouseLeave={() => setHover(null)}
                onFocus={() => setHover(n.id)}
                onBlur={() => setHover(null)}
                className={`cursor-pointer focus:outline-none [&:focus>circle]:stroke-sky-400 [&:focus>circle]:stroke-[3px] ${dim ? 'opacity-30' : ''}`}
              >
                <title>
                  {n.type} {n.canonical} · {n.event_count} events
                </title>
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={isFocus ? 9 : 6}
                  className={`${typeStyle(n.type).fill} ${isFocus ? 'stroke-white stroke-2 dark:stroke-slate-900' : ''}`}
                />
                <text
                  x={p.x + 14}
                  y={p.y + 4}
                  className={`fill-slate-800 stroke-white text-[12px] [paint-order:stroke] [stroke-width:3px] dark:fill-slate-100 dark:stroke-slate-900 ${isFocus ? 'font-bold' : ''}`}
                >
                  {label(n.canonical)}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
      {graph.truncated && <p className="text-xs text-amber-700">Graph truncated at the node/edge cap.</p>}
      <details className="text-sm">
        <summary className="cursor-pointer text-slate-600 dark:text-slate-400">All links as a table ({graph.edges.length})</summary>
        <table className="mt-2 w-full text-left text-xs">
          <caption className="sr-only">Graph edges</caption>
          <thead className="text-slate-500 uppercase">
            <tr>
              <th scope="col" className="py-1">From</th>
              <th scope="col">Relation</th>
              <th scope="col">To</th>
              <th scope="col" className="text-right">Count</th>
            </tr>
          </thead>
          <tbody>
            {graph.edges.map((e) => (
              <tr key={`${e.src_entity}-${e.dst_entity}-${e.relation}`} className="border-t border-slate-100 dark:border-slate-800">
                <td className="py-1 break-all">{name.get(e.src_entity)}</td>
                <td className="font-mono">{e.relation}</td>
                <td className="break-all">{name.get(e.dst_entity)}</td>
                <td className="text-right tabular-nums">{e.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}
