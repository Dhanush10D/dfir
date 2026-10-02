import type { Histogram as HistogramData } from '@/api/types'
import { formatUtc } from '@/lib/format'

/**
 * Events over time. Each bar is a button: activating it zooms the time range to that bucket
 * (keyboard accessible "brush to zoom"). Heights are set through React's style object (CSSOM),
 * which the strict CSP allows.
 */
export function Histogram({
  data,
  onZoom,
}: {
  data: HistogramData
  onZoom: (from: string, to: string) => void
}) {
  if (data.buckets.length === 0) {
    return <p className="text-sm text-slate-500">No events in range.</p>
  }
  const max = Math.max(...data.buckets.map((b) => b.count), 1)
  const step = data.interval_seconds * 1000
  return (
    <figure aria-label="Events over time">
      <div className="flex h-24 items-end gap-px" role="group" aria-label={`Histogram, ${data.total} events`}>
        {data.buckets.map((b) => {
          const start = new Date(b.ts)
          // The API's `to` is inclusive at microsecond precision: end on the bucket's last
          // microsecond, or events after the last whole second would drop out of the zoom.
          const end = new Date(start.getTime() + step - 1).toISOString().replace('Z', '999Z')
          const label = `${formatUtc(b.ts)}: ${b.count} events`
          return (
            <button
              key={b.ts}
              type="button"
              title={label}
              aria-label={`${label}. Zoom in`}
              onClick={() => onZoom(start.toISOString(), end)}
              className="min-w-0.5 flex-1 bg-sky-600 hover:bg-sky-800 focus-visible:ring-2 focus-visible:ring-sky-500 disabled:bg-slate-200"
              style={{ height: `${Math.max((b.count / max) * 100, b.count ? 4 : 1)}%` }}
              disabled={b.count === 0}
            />
          )
        })}
      </div>
      <figcaption className="mt-1 flex justify-between text-xs text-slate-500">
        <span>{formatUtc(data.from)}</span>
        <span>
          {data.total} events · {data.interval_seconds}s buckets
        </span>
        <span>{formatUtc(data.to)}</span>
      </figcaption>
    </figure>
  )
}
