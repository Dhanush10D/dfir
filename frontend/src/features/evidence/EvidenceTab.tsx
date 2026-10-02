import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api, saveBlob } from '@/api/endpoints'
import type { Evidence, VerifyResult } from '@/api/types'
import { Dialog } from '@/components/Dialog'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatBytes, formatUtc, shortHash } from '@/lib/format'

const KINDS = ['log', 'evtx', 'file', 'triage_bundle', 'memory', 'disk_image', 'pcap', 'cloud_export']

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
  const [kind, setKind] = useState('log')
  const upload = useMutation({
    mutationFn: () => api.upload(caseId, file as File, kind),
    onSuccess: () => {
      setFile(null)
      // The upload response is shown immediately, while invalidation makes the evidence list
      // authoritative again after the server has recorded the new custody state.
      void client.invalidateQueries({ queryKey: ['evidence', caseId] })
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    if (file) upload.mutate()
  }
  return (
    <form onSubmit={submit} className="mt-3 flex flex-wrap items-end gap-2" aria-label="Upload evidence">
      <label className="text-sm">
        <span className="mb-1 block font-medium">File</span>
        <input type="file" className="text-sm" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      </label>
      <label className="text-sm">
        <span className="mb-1 block font-medium">Kind</span>
        <select className={inputClass} value={kind} onChange={(e) => setKind(e.target.value)}>
          {KINDS.map((k) => (
            <option key={k}>{k}</option>
          ))}
        </select>
      </label>
      <Button type="submit" variant="primary" disabled={!file || upload.isPending}>
        {upload.isPending ? 'Uploading…' : 'Upload'}
      </Button>
      <ErrorMessage error={upload.error} />
      {upload.data && (
        <p role="status" className="text-sm">
          Stored {upload.data.label}: SHA-256 <span className="font-mono">{upload.data.sha256}</span>
        </p>
      )}
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
  const [custody, setCustody] = useState<Evidence | null>(null)
  const [verified, setVerified] = useState<Record<string, VerifyResult>>({})
  const verify = useMutation({
    mutationFn: (id: string) => api.verify(id),
    onSuccess: (res, id) => {
      setVerified((v) => ({ ...v, [id]: res }))
      void client.invalidateQueries({ queryKey: ['evidence', caseId] })
    },
  })
  const process = useMutation({
    mutationFn: (id: string) => api.process(id),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['jobs', caseId] }),
  })
  const exportPackage = useMutation({
    mutationFn: (id: string) => api.exportPackage(id),
    onSuccess: ({ blob, filename }) => saveBlob(blob, filename),
  })

  return (
    <div className="space-y-4">
      <Panel title="Evidence">
        {list.isPending && <Loading />}
        <ErrorMessage error={list.error ?? verify.error ?? process.error ?? exportPackage.error} />
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
                  <th scope="col">Actions</th>
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
                      <td className="space-x-1 whitespace-nowrap">
                        {can('custody:view') && (
                          <Button onClick={() => setCustody(ev)} aria-label={`Custody chain of ${ev.label}`}>
                            Custody
                          </Button>
                        )}
                        {can('custody:view') && (
                          <Button
                            onClick={() => exportPackage.mutate(ev.id)}
                            disabled={exportPackage.isPending}
                            title="Signed package: manifest, custody chain and signature (no original bytes)"
                          >
                            Export package
                          </Button>
                        )}
                        {can('evidence:verify') && (
                          <Button onClick={() => verify.mutate(ev.id)} disabled={verify.isPending}>
                            Verify
                          </Button>
                        )}
                        {can('evidence:add') && (
                          <Button onClick={() => process.mutate(ev.id)} disabled={process.isPending}>
                            {ev.kind === 'triage_bundle' ? 'Ingest bundle' : 'Process'}
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
