import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { EventRow } from '@/api/types'
import { Dialog } from '@/components/Dialog'
import { Button, ErrorMessage, inputClass, Loading } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

const FIELDS: (keyof EventRow)[] = [
  'ts',
  'ts_original',
  'source_type',
  'source_file',
  'source_record_id',
  'host',
  'user',
  'event_code',
  'event_category',
  'action',
  'outcome',
  'process_name',
  'pid',
  'ppid',
  'cmdline',
  'file_path',
  'file_hash',
  'src_ip',
  'src_port',
  'dst_ip',
  'dst_port',
  'protocol',
  'registry_key',
  'message',
  'parser_name',
]
const PIVOTS = new Set(['host', 'user', 'src_ip', 'dst_ip', 'process_name', 'file_hash', 'event_code'])

/** Row detail: fields, raw record (as text), pivots, context, bookmark and note actions. */
export function EventDrawer({
  event,
  onClose,
  onPivot,
}: {
  event: EventRow
  onClose: () => void
  onPivot: (field: string, value: string) => void
}) {
  const { caseId, can } = useCase()
  const client = useQueryClient()
  const detail = useQuery({
    queryKey: ['event', caseId, event.id],
    queryFn: ({ signal }) => api.event(caseId, event.id, signal),
  })
  const [minutes, setMinutes] = useState(5)
  const context = useMutation({ mutationFn: () => api.context(caseId, event.id, minutes) })
  const bookmark = useMutation({
    mutationFn: () => api.addBookmark(caseId, 'event', event.id),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['bookmarks', caseId] }),
  })
  const [note, setNote] = useState('')
  const addNote = useMutation({
    mutationFn: () => api.createNote(caseId, { body_md: note, target_type: 'event', target_id: event.id }),
    onSuccess: () => {
      setNote('')
      void client.invalidateQueries({ queryKey: ['notes', caseId] })
    },
  })

  function submitNote(e: FormEvent) {
    e.preventDefault()
    if (note.trim()) addNote.mutate()
  }

  return (
    <Dialog title={`Event ${formatUtc(event.ts)} ${event.event_code ?? ''}`} onClose={onClose} wide>
      <div className="space-y-4">
        <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-sm">
          {FIELDS.map((f) => {
            const value = event[f]
            if (value === null || value === undefined || value === '') return null
            const text = f === 'ts' ? formatUtc(String(value)) : String(value)
            return (
              <div key={f} className="contents">
                <dt className="text-slate-500">{f}</dt>
                <dd className="flex items-start gap-2 break-all">
                  <span className={f === 'cmdline' || f === 'message' ? 'whitespace-pre-wrap' : ''}>{text}</span>
                  {PIVOTS.has(f) && (
                    <button
                      type="button"
                      className="shrink-0 text-xs text-sky-700 hover:underline dark:text-sky-400"
                      onClick={() => onPivot(f, String(value))}
                      aria-label={`Filter timeline on ${f} ${text}`}
                    >
                      filter
                    </button>
                  )}
                </dd>
              </div>
            )
          })}
          {event.attack_tags.length > 0 && (
            <>
              <dt className="text-slate-500">attack_tags</dt>
              <dd>{event.attack_tags.join(', ')}</dd>
            </>
          )}
        </dl>

        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm">
            <span className="mb-1 block font-medium">Context (± minutes, same host)</span>
            <input
              type="number"
              min={1}
              max={1440}
              className={`${inputClass} w-24`}
              value={minutes}
              onChange={(e) => setMinutes(Math.max(1, Math.min(1440, Number(e.target.value) || 1)))}
            />
          </label>
          <Button onClick={() => context.mutate()} disabled={context.isPending}>
            Show context
          </Button>
          {can('investigate') && (
            <Button onClick={() => bookmark.mutate()} disabled={bookmark.isPending || bookmark.isSuccess}>
              {bookmark.isSuccess ? 'Bookmarked' : 'Bookmark'}
            </Button>
          )}
        </div>
        <ErrorMessage error={context.error ?? bookmark.error} />
        {context.data && (
          <ol className="max-h-48 overflow-y-auto text-xs" aria-label="Context events">
            {context.data.items.map((e) => (
              <li key={e.id} className={e.id === event.id ? 'font-semibold' : ''}>
                <span className="font-mono">{formatUtc(e.ts)}</span> {e.event_code ?? ''} {e.message ?? ''}
              </li>
            ))}
          </ol>
        )}

        {can('investigate') && (
          <form onSubmit={submitNote} className="space-y-2" aria-label="Add a note to this event">
            <label className="block text-sm">
              <span className="mb-1 block font-medium">Note</span>
              <textarea
                className={`${inputClass} w-full`}
                rows={3}
                maxLength={20000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </label>
            <Button type="submit" disabled={addNote.isPending || !note.trim()}>
              Add note
            </Button>
            <ErrorMessage error={addNote.error} />
            {addNote.isSuccess && <p role="status" className="text-sm">Note saved.</p>}
          </form>
        )}

        <section aria-label="Raw record">
          <h3 className="text-sm font-medium">Raw record</h3>
          {detail.isPending && <Loading />}
          <ErrorMessage error={detail.error} />
          {detail.data && (
            <pre className="max-h-80 overflow-auto rounded bg-slate-100 p-2 text-xs dark:bg-slate-800">
              {JSON.stringify(detail.data.raw, null, 2)}
            </pre>
          )}
        </section>
      </div>
    </Dialog>
  )
}
