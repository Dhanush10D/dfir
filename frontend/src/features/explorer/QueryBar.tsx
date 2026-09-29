import { useId, useState, type FormEvent } from 'react'

import { Button, inputClass } from '@/components/ui'
import { FIELDS, validateQuery, type QueryError } from '@/lib/searchLanguage'

export interface QueryState {
  q: string
  from: string
  to: string
}

/** Query + time range. Validates with the client mirror of the grammar before submitting. */
export function QueryBar({
  initial,
  serverError,
  onSubmit,
}: {
  initial: QueryState
  serverError?: { message: string; position?: number } | null
  onSubmit: (state: QueryState) => void
}) {
  const [q, setQ] = useState(initial.q)
  const [from, setFrom] = useState(initial.from)
  const [to, setTo] = useState(initial.to)
  const [error, setError] = useState<QueryError | null>(null)
  const errId = useId()
  const hintId = useId()

  function submit(e: FormEvent) {
    e.preventDefault()
    const err = validateQuery(q)
    setError(err)
    if (err) return
    onSubmit({ q: q.trim(), from: from.trim(), to: to.trim() })
  }

  const shown = error
    ? { message: error.message, position: error.position }
    : serverError ?? null

  return (
    <form onSubmit={submit} className="space-y-2" aria-label="Timeline search">
      <div className="flex flex-wrap items-end gap-2">
        <label className="min-w-72 flex-1 text-sm">
          <span className="mb-1 block font-medium">Query</span>
          <input
            className={`${inputClass} w-full font-mono`}
            value={q}
            spellCheck={false}
            maxLength={2000}
            placeholder='event_code:4625 AND src_ip:203.0.113.0/24'
            aria-invalid={shown ? true : undefined}
            aria-describedby={shown ? errId : hintId}
            onChange={(e) => {
              setQ(e.target.value)
              if (error) setError(null)
            }}
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">From (UTC, ISO)</span>
          <input
            className={`${inputClass} w-52 font-mono`}
            value={from}
            placeholder="2026-09-14T00:00:00Z"
            onChange={(e) => setFrom(e.target.value)}
          />
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">To (UTC, ISO)</span>
          <input
            className={`${inputClass} w-52 font-mono`}
            value={to}
            placeholder="2026-09-15T00:00:00Z"
            onChange={(e) => setTo(e.target.value)}
          />
        </label>
        <Button type="submit" variant="primary">
          Run
        </Button>
      </div>
      {shown ? (
        <p id={errId} role="alert" className="text-sm text-red-700 dark:text-red-400">
          <span aria-hidden="true">&#x2715; </span>
          {shown.message}
          {shown.position !== undefined && ` (at character ${shown.position + 1})`}
        </p>
      ) : (
        <p id={hintId} className="text-xs text-slate-500">
          Fields: {Object.keys(FIELDS).join(', ')}. AND / OR / NOT, ( ), field:[a TO b], quotes,
          wildcards (cmdline:*-enc*).
        </p>
      )}
    </form>
  )
}
