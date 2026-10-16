import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState, type FormEvent } from 'react'

import { ApiError } from '@/api/client'
import { api, saveBlob } from '@/api/endpoints'
import type { Evidence, VerifyResult } from '@/api/types'
import { Dialog } from '@/components/Dialog'
import { Button, ErrorMessage, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatBytes, formatUtc, shortHash } from '@/lib/format'

function CustodyDialog({ evidence, onClose }: { evidence: Evidence; onClose: () => void }) {
  const q = useQuery({
    queryKey: ['custody', evidence.id],
    queryFn: ({ signal }) => api.custody(evidence.id, signal),
  })
  return (
    <Dialog title={`Chain of custody: ${evidence.label}`} onClose={onClose} wide>
      {q.isPending && <Loading />}
      <ErrorMessage error={q.error} />
      {q.data && (
        <ol className="space-y-2 text-sm">
          {q.data.entries.map((e) => (
            <li key={e.seq} className="rounded border border-slate-200 p-2 dark:border-slate-700">
              <div className="flex flex-wrap gap-x-3">
                <span className="font-mono">#{e.seq}</span>
                <span className="font-semibold">{e.action}</span>
                <span>{formatUtc(e.ts)}</span>
                <span>{e.actor_label}</span>
              </div>
              <div className="font-mono text-xs break-all text-slate-500">
                hash {e.entry_hash} · prev {shortHash(e.prev_hash, 16)} · key {e.key_id}
              </div>
            </li>
          ))}
        </ol>
      )}
    </Dialog>
  )
}

function UploadForm() {
  const { caseId } = useCase()
  const client = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [pickerKey, setPickerKey] = useState(0)
  const [autoProcess, setAutoProcess] = useState(true)
  // The server recognises the file from its name and first/last bytes (the same detection that
  // picks the parser) and decides the evidence kind; the analyst never has to choose it.
  const identify = useMutation({ mutationFn: (f: File) => api.identify(caseId, f) })
  const detected = identify.data && identify.variables === file ? identify.data : null
  function choose(f: File | null) {
    setFile(f)
    identify.reset()
    if (f) identify.mutate(f)
  }
  const upload = useMutation({
    mutationFn: async () => {
      const ev = await api.upload(caseId, file as File, detected?.kind ?? 'file')
      if (!autoProcess) return { ev, processing: 'skipped' as const, error: null }
      try {
        await api.process(ev.id)
        return { ev, processing: 'started' as const, error: null }
      } catch (err) {
        // The evidence is stored either way; report why processing did not start.
        return { ev, processing: 'failed' as const, error: err }
      }
    },
    onSuccess: () => {
      choose(null)
      setPickerKey((k) => k + 1) // clear the picker too, so the same file can be chosen again
      // The upload response is shown immediately, while invalidation makes the evidence list
      // authoritative again after the server has recorded the new custody state.
      void client.invalidateQueries({ queryKey: ['evidence', caseId] })
      void client.invalidateQueries({ queryKey: ['jobs', caseId] })
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    if (file) upload.mutate()
  }
  const noParser =
    upload.data?.error instanceof ApiError && upload.data.error.code === 'no_parser'
  return (
    <form onSubmit={submit} className="mt-3 flex flex-wrap items-end gap-2" aria-label="Upload evidence">
      <label className="text-sm">
        <span className="mb-1 block font-medium">File</span>
        <input
          key={pickerKey}
          type="file"
          className="cursor-pointer text-sm file:mr-3 file:cursor-pointer file:rounded file:border-0 file:bg-slate-200 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-slate-900 hover:file:bg-slate-300 dark:file:bg-slate-700 dark:file:text-slate-100 dark:hover:file:bg-slate-600"
          onChange={(e) => choose(e.target.files?.[0] ?? null)}
        />
      </label>
      <label className="flex items-center gap-1.5 self-center text-sm">
        <input type="checkbox" checked={autoProcess} onChange={(e) => setAutoProcess(e.target.checked)} />
        Process after upload
      </label>
      <Button
        type="submit"
        variant="primary"
        disabled={!file || upload.isPending || identify.isPending}
        title={file ? undefined : 'Choose a file first'}
      >
        {upload.isPending ? 'Uploading…' : 'Upload'}
      </Button>
      {!file && !upload.isPending && <p className="text-xs text-slate-500">Choose a file to enable Upload.</p>}
      {file && identify.isPending && <p className="w-full text-sm text-slate-500">Detecting the file type…</p>}
      {detected && (
        <p role="status" className="w-full text-sm">
          Detected: <span className="font-medium">{detected.description}</span>
          {detected.parser ? ` (parser ${detected.parser})` : ''}, stored as{' '}
          <span className="font-mono">{detected.kind}</span>.
        </p>
      )}
      {file && identify.isError && (
        <p className="w-full text-sm text-amber-700 dark:text-amber-400">
          Could not detect the file type; it will be stored as a generic file.
        </p>
      )}
      <ErrorMessage error={upload.error} />
      {upload.data && (
        <p role="status" className="w-full text-sm">
          Stored {upload.data.ev.label}: SHA-256 <span className="font-mono">{upload.data.ev.sha256}</span>.{' '}
          {upload.data.processing === 'started' && 'Processing started (see Jobs).'}
          {noParser && 'No parser recognises this file, so it is stored as evidence only.'}
        </p>
      )}
      {upload.data?.processing === 'failed' && !noParser && <ErrorMessage error={upload.data.error} />}
    </form>
  )
}

export function EvidenceTab() {
  const { caseId, can } = useCase()
  const client = useQueryClient()
  const list = useQuery({ queryKey: ['evidence', caseId], queryFn: ({ signal }) => api.evidence(caseId, signal) })
  const jobs = useQuery({
    queryKey: ['jobs', caseId],
    queryFn: ({ signal }) => api.jobs(caseId, signal),
    refetchInterval: (q) =>
      q.state.data?.items.some((j) => j.status === 'queued' || j.status === 'running') ? 3000 : false,
  })
  // Jobs create evidence too (a bundle ingest adds its members): refresh the list while jobs
  // run and once more when they finish, plus the overview counts.
  const active = jobs.data?.items.some((j) => j.status === 'queued' || j.status === 'running') ?? false
  const wasActive = useRef(false)
  useEffect(() => {
    if (active || wasActive.current) {
      void client.invalidateQueries({ queryKey: ['evidence', caseId] })
      if (!active) void client.invalidateQueries({ queryKey: ['summary', caseId] })
    }
    wasActive.current = active
  }, [jobs.dataUpdatedAt, active, caseId, client])
  const [custody, setCustody] = useState<Evidence | null>(null)
  const [verified, setVerified] = useState<Record<string, VerifyResult>>({})
  const [note, setNote] = useState<string | null>(null)
  // One button per action, run over every evidence item (one request per item, in order).
  const items = list.data?.items ?? []
  const stored = items.filter((ev) => !['uploading', 'uploaded', 'failed'].includes(ev.status))
  // Bundle members are processed by their bundle; an item with a job that did not fail is done.
  const handled = new Set(
    (jobs.data?.items ?? []).filter((j) => !['failed', 'cancelled'].includes(j.status)).map((j) => j.evidence_id),
  )
  const toProcess = stored.filter((ev) => !ev.parent_evidence_id && !handled.has(ev.id))
  const processAll = useMutation({
    mutationFn: async () => {
      let started = 0
      let noParser = 0
      const failed: string[] = []
      for (const ev of toProcess) {
        try {
          await api.process(ev.id)
          started += 1
        } catch (err) {
          if (err instanceof ApiError && err.code === 'no_parser') noParser += 1
          else failed.push(`${ev.label}: ${err instanceof Error ? err.message : 'failed'}`)
        }
      }
      return { started, noParser, failed }
    },
    onSuccess: ({ started, noParser, failed }) => {
      const parts = [`Processing started for ${started} item${started === 1 ? '' : 's'}`]
      if (noParser) parts.push(`${noParser} stored only (no parser recognises them)`)
      if (failed.length) parts.push(`not started: ${failed.join('; ')}`)
      setNote(parts.join(', ') + '.')
      void client.invalidateQueries({ queryKey: ['jobs', caseId] })
    },
  })
  const verifyAll = useMutation({
    mutationFn: async () => {
      const results: Record<string, VerifyResult> = {}
      for (const ev of stored) results[ev.id] = await api.verify(ev.id)
      return results
    },
    onSuccess: (results) => {
      setVerified(results)
      const total = Object.keys(results).length
      const bad = Object.values(results).filter((r) => !r.ok).length
      setNote(bad ? `${bad} of ${total} items FAILED the integrity check.` : `All ${total} items verified: hashes match.`)
      void client.invalidateQueries({ queryKey: ['evidence', caseId] })
    },
  })
  const exportAll = useMutation({
    mutationFn: async () => {
      for (const ev of stored) {
        const { blob, filename } = await api.exportPackage(ev.id)
        saveBlob(blob, filename)
        await new Promise((resolve) => setTimeout(resolve, 300)) // browsers drop downloads started too close together
      }
      return stored.length
    },
    onSuccess: (n) => setNote(`Downloaded ${n} signed evidence package${n === 1 ? '' : 's'}.`),
  })
  const busy = processAll.isPending || verifyAll.isPending || exportAll.isPending
  const actions = (
    <div className="flex flex-wrap gap-1">
      {can('evidence:add') && (
        <Button
          variant="primary"
          onClick={() => processAll.mutate()}
          disabled={busy || toProcess.length === 0}
          title={toProcess.length ? 'Process every item that has not been processed yet' : 'Everything has been processed'}
        >
          {processAll.isPending ? 'Processing…' : `Process all (${toProcess.length})`}
        </Button>
      )}
      {can('evidence:verify') && (
        <Button onClick={() => verifyAll.mutate()} disabled={busy || stored.length === 0} title="Re-hash every stored original and compare">
          {verifyAll.isPending ? 'Verifying…' : 'Verify all'}
        </Button>
      )}
      {can('custody:view') && (
        <Button
          onClick={() => exportAll.mutate()}
          disabled={busy || stored.length === 0}
          title="Signed packages: manifest, custody chain and signature (no original bytes), one per item"
        >
          {exportAll.isPending ? 'Exporting…' : 'Export all packages'}
        </Button>
      )}
    </div>
  )

  return (
    <div className="space-y-4">
      <Panel title="Evidence" actions={items.length > 0 ? actions : undefined}>
        {list.isPending && <Loading />}
        <ErrorMessage error={list.error ?? processAll.error ?? verifyAll.error ?? exportAll.error} />
        {note && (
          <p role="status" className="mb-2 text-sm">
            {note}
          </p>
        )}
        {list.data && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Evidence items</caption>
              <thead className="text-xs text-slate-500 uppercase">
                <tr>
                  <th scope="col">Label</th>
                  <th scope="col">Name</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Size</th>
                  <th scope="col">SHA-256</th>
                  <th scope="col">Status</th>
                  <th scope="col">Chain of custody</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((ev) => {
                  const result = verified[ev.id]
                  const parent = ev.parent_evidence_id
                    ? list.data.items.find((p) => p.id === ev.parent_evidence_id)
                    : undefined
                  return (
                    <tr key={ev.id} className="border-t border-slate-100 align-top dark:border-slate-800">
                      <td className="py-1.5 font-mono">
                        {ev.label}
                        {ev.parent_evidence_id && (
                          <span className="block text-xs text-slate-500">
                            from {parent ? parent.label : 'bundle'}
                          </span>
                        )}
                      </td>
                      <td className="max-w-xs break-all">{ev.original_name}</td>
                      <td>{ev.kind}</td>
                      <td>{formatBytes(ev.size_bytes)}</td>
                      <td className="font-mono text-xs" title={ev.sha256 ?? undefined}>
                        {shortHash(ev.sha256, 16)}
                      </td>
                      <td>
                        {ev.status}
                        {result && (
                          <span role="status" className={`ml-1 font-semibold ${result.ok ? 'text-emerald-700' : 'text-red-700'}`}>
                            {result.ok ? '✓ verified' : '✕ integrity failure'}
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap">
                        {can('custody:view') && (
                          <Button onClick={() => setCustody(ev)} aria-label={`Custody chain of ${ev.label}`}>
                            Custody
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
        {can('evidence:add') && <UploadForm />}
      </Panel>
      <Panel title="Jobs">
        {jobs.data && (
          <ul className="text-sm">
            {jobs.data.items.map((j) => (
              <li key={j.id} className="flex flex-wrap gap-x-3">
                <span className="font-mono text-xs">{j.id.slice(0, 8)}</span>
                <span>{j.kind}{j.parser ? ` (${j.parser})` : ''}</span>
                <span className="font-semibold">{j.status}</span>
                <span>{Math.round(j.progress * 100)}%</span>
                <span>{formatUtc(j.queued_at)}</span>
                {j.error && <span className="text-red-700">{j.error}</span>}
              </li>
            ))}
          </ul>
        )}
      </Panel>
      {custody && <CustodyDialog evidence={custody} onClose={() => setCustody(null)} />}
    </div>
  )
}
