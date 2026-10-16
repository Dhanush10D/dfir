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
        <thead className="border-b border-slate-200 text-xs text-slate-500 uppercase dark:border-slate-700">
          <tr className="[&>th]:px-3 [&>th]:py-2 [&>th]:font-semibold [&>th]:whitespace-nowrap">
            <th scope="col" className="pl-0!">Time (UTC)</th>
            <th scope="col">Source</th>
            <th scope="col">Host</th>
            <th scope="col">User</th>
            <th scope="col">Code</th>
            <th scope="col" className="w-full">Summary</th>
            <th scope="col" className="pr-0!">ATT&amp;CK</th>
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
              className="cursor-pointer border-t border-slate-100 align-top hover:bg-sky-50 focus:bg-sky-100 focus:outline-none dark:border-slate-800 dark:hover:bg-slate-800 dark:focus:bg-slate-700 [&>td]:px-3 [&>td]:py-2"
            >
              <td className="pl-0! font-mono text-xs whitespace-nowrap">{formatUtc(ev.ts)}</td>
              <td className="whitespace-nowrap">{ev.source_type}</td>
              <td className="whitespace-nowrap">{ev.host ?? ''}</td>
              <td className="max-w-[16rem] wrap-anywhere">{ev.user ?? ''}</td>
              <td className="font-mono whitespace-nowrap">{ev.event_code ?? ''}</td>
              <td className="min-w-[20rem] wrap-anywhere">{ev.message ?? ''}</td>
              <td className="pr-0!">
                <div className="flex flex-col items-start gap-1">
                  {ev.attack_tags.map((tag) => (
                    <span
                      key={tag}
                      className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs whitespace-nowrap text-slate-700 dark:bg-slate-800 dark:text-slate-300"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </td>
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
