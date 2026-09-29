import { useQuery } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { ProcessNode } from '@/api/types'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

const FLAG_TEXT: Record<string, string> = {
  suspicious_parent: 'suspicious parent',
  cycle_broken: 'cycle broken',
}

function NodeRow({ node }: { node: ProcessNode }) {
  return (
    <li
      role="treeitem"
      aria-level={node.depth + 1}
      aria-selected={false}
      tabIndex={-1}
      className="border-l border-slate-200 py-0.5 dark:border-slate-700"
    >
      {/* depth indentation via a spacer width (CSSOM style, allowed by the CSP) */}
      <div className="flex items-start gap-1" style={{ paddingLeft: `${node.depth * 1.25}rem` }}>
        <span className="font-mono text-xs text-slate-500">{node.pid ?? '?'}</span>
        <span className={`font-medium ${node.kind === 'synthetic' ? 'italic text-slate-500' : ''}`}>
          {node.name ?? '(unknown)'}
        </span>
        {node.kind !== 'created' && <span className="text-xs text-slate-500">[{node.kind}]</span>}
        {node.flags.map((f) => (
          <span key={f} className="rounded bg-red-100 px-1 text-xs font-semibold text-red-900">
            &#9888; {FLAG_TEXT[f] ?? f}
          </span>
        ))}
        {node.alerts > 0 && (
          <span className="rounded bg-orange-200 px-1 text-xs font-semibold text-orange-900">
            {node.alerts} alert{node.alerts === 1 ? '' : 's'}
          </span>
        )}
        <span className="text-xs text-slate-500">{formatUtc(node.ts)}</span>
        {node.user && <span className="text-xs text-slate-500">{node.user}</span>}
      </div>
      {node.cmdline && (
        <code className="block text-xs break-all whitespace-pre-wrap text-slate-600 dark:text-slate-300" style={{ paddingLeft: `${node.depth * 1.25 + 2}rem` }}>
          {node.cmdline}
        </code>
      )}
    </li>
  )
}

export function ProcessTreeTab() {
  const { caseId } = useCase()
  const [draft, setDraft] = useState('')
  const [host, setHost] = useState('')
  const hosts = useQuery({
    queryKey: ['proc-hosts', caseId],
    queryFn: ({ signal }) => api.facets(caseId, { query: 'pid:*' }, ['host'], signal),
  })
  const tree = useQuery({
    queryKey: ['proctree', caseId, host],
    queryFn: ({ signal }) => api.processTree(caseId, host, signal),
    enabled: host.length > 0,
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    setHost(draft.trim())
  }
  return (
    <Panel title="Process tree">
      <form onSubmit={submit} className="mb-3 flex flex-wrap items-end gap-2" aria-label="Choose host">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Host</span>
          <input className={inputClass} list="proc-hosts" value={draft} maxLength={255} onChange={(e) => setDraft(e.target.value)} />
          <datalist id="proc-hosts">
            {hosts.data?.fields.host?.map((h) => (
              <option key={h.value} value={h.value} />
            ))}
          </datalist>
        </label>
        <Button type="submit" variant="primary" disabled={!draft.trim()}>
          Show
        </Button>
      </form>
      {tree.isFetching && <Loading />}
      <ErrorMessage error={tree.error} />
      {tree.data && (
        <>
          <p className="mb-2 text-xs text-slate-500">
            {tree.data.nodes.length} processes
            {tree.data.truncated && ' · truncated at the node cap'}
            {tree.data.cycles_broken > 0 && ` · ${tree.data.cycles_broken} parent cycle(s) refused`}
            {tree.data.depth_capped > 0 && ` · ${tree.data.depth_capped} below the depth cap hidden`}
          </p>
          <ul role="tree" aria-label={`Processes on ${tree.data.host}`} className="text-sm">
            {tree.data.nodes.map((n) => (
              <NodeRow key={n.key} node={n} />
            ))}
          </ul>
        </>
      )}
    </Panel>
  )
}
