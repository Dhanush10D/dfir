import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { Note } from '@/api/types'
import { Dialog } from '@/components/Dialog'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

/** Notes are stored as typed (Markdown source) and shown as plain text: never rendered as HTML. */
function NoteBody({ text }: { text: string }) {
  return <p className="text-sm break-words whitespace-pre-wrap">{text}</p>
}

function History({ noteId, onClose }: { noteId: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['note', noteId], queryFn: ({ signal }) => api.note(noteId, signal) })
  return (
    <Dialog title="Note history" onClose={onClose}>
      {q.isPending && <Loading />}
      <ErrorMessage error={q.error} />
      <ol className="space-y-2">
        {q.data?.versions.map((v) => (
          <li key={v.version} className="rounded border border-slate-200 p-2 dark:border-slate-700">
            <p className="text-xs text-slate-500">
              v{v.version} {v.action} · {formatUtc(v.created_at)}
              {v.reason ? ` · ${v.reason}` : ''}
            </p>
            <NoteBody text={v.body_md} />
          </li>
        ))}
      </ol>
    </Dialog>
  )
}

function NoteItem({ note }: { note: Note }) {
  const { caseId, can, userId } = useCase()
  const client = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [text, setText] = useState(note.body_md)
  const [history, setHistory] = useState(false)
  const refresh = () => void client.invalidateQueries({ queryKey: ['notes', caseId] })
  const edit = useMutation({
    mutationFn: () => api.editNote(note.id, text, note.version),
    onSuccess: () => {
      setEditing(false)
      refresh()
    },
  })
  const retract = useMutation({ mutationFn: () => api.retractNote(note.id, note.version), onSuccess: refresh })
  const mine = note.author_id === userId
  function submit(e: FormEvent) {
    e.preventDefault()
    if (text.trim()) edit.mutate()
  }
  return (
    <li className="rounded border border-slate-200 p-2 dark:border-slate-700">
      <p className="text-xs text-slate-500">
        {formatUtc(note.created_at)} · v{note.version}
        {note.target_type ? ` · on ${note.target_type} ${note.target_id ?? ''}` : ''}
        {note.retracted_at ? ' · retracted' : ''}
      </p>
      {editing ? (
        <form onSubmit={submit} className="space-y-1" aria-label="Edit note">
          <label className="block text-sm">
            <span className="sr-only">Note text</span>
            <textarea className={`${inputClass} w-full`} rows={3} maxLength={20000} value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <Button type="submit" variant="primary" disabled={edit.isPending}>
            Save
          </Button>{' '}
          <Button onClick={() => setEditing(false)}>Cancel</Button>
        </form>
      ) : (
        <NoteBody text={note.body_md} />
      )}
      <ErrorMessage error={edit.error ?? retract.error} />
      <div className="mt-1 flex gap-1">
        <Button variant="ghost" onClick={() => setHistory(true)}>
          History
        </Button>
        {!note.retracted_at && mine && can('investigate') && !editing && (
          <Button variant="ghost" onClick={() => setEditing(true)}>
            Edit
          </Button>
        )}
        {!note.retracted_at && can('investigate') && (mine || can('case:manage')) && (
          <Button variant="ghost" onClick={() => retract.mutate()} disabled={retract.isPending}>
            Retract
          </Button>
        )}
      </div>
      {history && <History noteId={note.id} onClose={() => setHistory(false)} />}
    </li>
  )
}

export function NotesTab() {
  const { caseId, can, userId } = useCase()
  const client = useQueryClient()
  const [includeRetracted, setIncludeRetracted] = useState(false)
  const notes = useQuery({
    queryKey: ['notes', caseId, includeRetracted],
    queryFn: ({ signal }) => api.notes(caseId, includeRetracted, signal),
  })
  const bookmarks = useQuery({
    queryKey: ['bookmarks', caseId],
    queryFn: ({ signal }) => api.bookmarks(caseId, signal),
    enabled: can('investigate'),
  })
  const [body, setBody] = useState('')
  const create = useMutation({
    mutationFn: () => api.createNote(caseId, { body_md: body, target_type: 'case' }),
    onSuccess: () => {
      setBody('')
      void client.invalidateQueries({ queryKey: ['notes', caseId] })
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteBookmark(caseId, id),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['bookmarks', caseId] }),
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    if (body.trim()) create.mutate()
  }
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Panel title="Notes">
        <label className="mb-2 flex items-center gap-2 text-sm">
          <input type="checkbox" checked={includeRetracted} onChange={(e) => setIncludeRetracted(e.target.checked)} />
          Show retracted notes
        </label>
        {can('investigate') && (
          <form onSubmit={submit} className="mb-3 space-y-1" aria-label="Add a case note">
            <label className="block text-sm">
              <span className="mb-1 block font-medium">New note</span>
              <textarea className={`${inputClass} w-full`} rows={3} maxLength={20000} value={body} onChange={(e) => setBody(e.target.value)} />
            </label>
            <Button type="submit" variant="primary" disabled={create.isPending || !body.trim()}>
              Add note
            </Button>
            <ErrorMessage error={create.error} />
          </form>
        )}
        {notes.isPending && <Loading />}
        <ErrorMessage error={notes.error} />
        <ul className="space-y-2">
          {notes.data?.items.map((n) => (
            <NoteItem key={`${n.id}-${n.version}`} note={n} />
          ))}
        </ul>
      </Panel>
      {can('investigate') && (
        <Panel title="Bookmarks">
          {bookmarks.isPending && <Loading />}
          <ErrorMessage error={bookmarks.error ?? remove.error} />
          <ul className="space-y-1 text-sm">
            {bookmarks.data?.map((b) => (
              <li key={b.id} className="flex items-start justify-between gap-2">
                <span className="break-all">
                  <span className="text-xs text-slate-500">
                    {b.target_type} · {b.user_name ?? ''} ·{' '}
                  </span>
                  {b.event ? `${formatUtc(b.event.ts)} ${b.event.event_code ?? ''} ${b.event.message ?? ''}` : b.target_id}
                  {b.comment ? ` — ${b.comment}` : ''}
                </span>
                {(b.user_id === userId || can('case:manage')) && (
                  <Button variant="ghost" onClick={() => remove.mutate(b.id)} aria-label="Remove bookmark">
                    Remove
                  </Button>
                )}
              </li>
            ))}
          </ul>
          {bookmarks.data?.length === 0 && <p className="text-sm text-slate-500">No bookmarks.</p>}
        </Panel>
      )}
    </div>
  )
}
