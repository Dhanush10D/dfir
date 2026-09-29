import { useRef, useState, type KeyboardEvent } from 'react'

import type { EventRow } from '@/api/types'
import { formatUtc } from '@/lib/format'

/**
 * Timeline table. Every value is attacker-controlled evidence: it is rendered as React text only
 * (escaped), never as HTML. Keyboard: the table has one tab stop (roving tabindex); ArrowUp/Down,
 * Home/End move between rows, Enter or Space opens the row.
 */
export function EventTable({
  events,
  onOpen,
  caption = 'Timeline events',
}: {
  events: EventRow[]
  onOpen: (event: EventRow) => void
  caption?: string
}) {
  const [active, setActive] = useState(0)
  const rows = useRef<(HTMLTableRowElement | null)[]>([])

  function focusRow(i: number) {
    const next = Math.max(0, Math.min(events.length - 1, i))
    setActive(next)
    rows.current[next]?.focus()
  }

  function onKeyDown(e: KeyboardEvent<HTMLTableRowElement>, i: number) {
    const moves: Record<string, number> = { ArrowDown: i + 1, ArrowUp: i - 1, Home: 0, End: events.length - 1 }
    const target = moves[e.key]
    if (target !== undefined) {
      e.preventDefault()
      focusRow(target)
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      const ev = events[i]
      if (ev) onOpen(ev)
    }
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm" aria-rowcount={events.length + 1}>
        <caption className="sr-only">{caption}. Use arrow keys to move and Enter to open.</caption>
        <thead className="text-xs text-slate-500 uppercase">
          <tr>
            <th scope="col" className="py-1 whitespace-nowrap">Time (UTC)</th>
            <th scope="col">Source</th>
            <th scope="col">Host</th>
            <th scope="col">User</th>
            <th scope="col">Code</th>
            <th scope="col">Summary</th>
            <th scope="col">ATT&amp;CK</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev, i) => (
            <tr
              key={ev.id}
              ref={(el) => {
                rows.current[i] = el
              }}
              tabIndex={i === active ? 0 : -1}
              aria-rowindex={i + 2}
              onClick={() => {
                setActive(i)
                onOpen(ev)
              }}
              onKeyDown={(e) => onKeyDown(e, i)}
              className="cursor-pointer border-t border-slate-100 align-top hover:bg-sky-50 focus:bg-sky-100 focus:outline-none dark:border-slate-800 dark:hover:bg-slate-800 dark:focus:bg-slate-700"
            >
              <td className="py-1 font-mono text-xs whitespace-nowrap">{formatUtc(ev.ts)}</td>
              <td>{ev.source_type}</td>
              <td className="break-all">{ev.host ?? ''}</td>
              <td className="break-all">{ev.user ?? ''}</td>
              <td className="font-mono">{ev.event_code ?? ''}</td>
              <td className="max-w-xl break-words">{ev.message ?? ''}</td>
              <td className="font-mono text-xs">{ev.attack_tags.join(' ')}</td>
            </tr>
          ))}
          {events.length === 0 && (
            <tr>
              <td colSpan={7} className="py-2 text-slate-500">
                No events.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
