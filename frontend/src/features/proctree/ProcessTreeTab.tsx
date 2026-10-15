import { useQuery } from '@tanstack/react-query'
import { useMemo, useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import type { ProcessNode } from '@/api/types'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { formatUtc } from '@/lib/format'

const FLAG_TEXT: Record<string, string> = {
  suspicious_parent: 'suspicious parent',
  cycle_broken: 'cycle broken',
}

// How the server learned about the process (backend/app/analysis/proctree.py).
const KIND: Record<string, { label: string; help: string; className: string }> = {
  created: {
    label: 'created',
    help: 'Seen being started (Sysmon 1 / Security 4688)',
    className: 'bg-sky-100 text-sky-900 dark:bg-sky-900/40 dark:text-sky-200',
  },
  observed: {
    label: 'observed',
    help: 'Only seen in other events that carry its pid; no start event',
    className: 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
  },
  synthetic: {
    label: 'inferred parent',
    help: 'Never seen directly; inferred from a child’s parent pid',
    className: 'border border-dashed border-slate-400 text-slate-600 dark:text-slate-300',
  },
}

const chipClass = 'rounded px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap'

function KindChip({ kind }: { kind: string }) {
  const k = KIND[kind]
  return (
    <span title={k?.help} className={`${chipClass} font-medium ${k?.className ?? ''}`}>
      {k?.label ?? kind}
    </span>
  )
}

function NodeRow({
  node,
  collapsed,
  onToggle,
}: {
  node: ProcessNode
  collapsed: boolean
  onToggle: () => void
}) {
  const flagged = node.alerts > 0 || node.flags.length > 0
  return (
    <tr
      className={`border-t border-slate-100 align-top dark:border-slate-800 ${
        flagged ? 'bg-orange-50 dark:bg-orange-950/20' : ''
      }`}
    >
      <td className="py-1.5 pr-3">
        {/* depth indentation via a spacer width (CSSOM style, allowed by the CSP) */}
        <div className="flex items-start gap-1.5" style={{ paddingLeft: `${node.depth * 1.5}rem` }}>
          {node.children > 0 ? (
            <button
              type="button"
              onClick={onToggle}
              aria-expanded={!collapsed}
              aria-label={`${collapsed ? 'Expand' : 'Collapse'} ${node.name ?? 'process'} ${node.pid ?? ''}`}
              className="w-4 shrink-0 text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"
            >
              {collapsed ? '▸' : '▾'}
            </button>
          ) : (
            <span aria-hidden="true" className="w-4 shrink-0 text-center text-slate-400">
              {node.depth > 0 ? '└' : '•'}
            </span>
          )}
          <div className="min-w-0">
            <span className={`font-medium ${node.kind === 'synthetic' ? 'text-slate-500 italic' : ''}`}>
              {node.name ?? '(unknown)'}
            </span>
            {node.children > 0 && (
              <span className="ml-2 text-xs text-slate-500">
                {node.children} child{node.children === 1 ? '' : 'ren'}
              </span>
            )}
            {node.cmdline && (
              <code className="mt-0.5 block text-xs break-all whitespace-pre-wrap text-slate-500 dark:text-slate-400">
                {node.cmdline}
              </code>
            )}
          </div>
        </div>
      </td>
      <td className="py-1.5 pr-3 font-mono text-xs">{node.pid ?? '?'}</td>
      <td className="py-1.5 pr-3 font-mono text-xs text-slate-500">{node.ppid ?? '–'}</td>
      <td className="py-1.5 pr-3 text-xs">{node.user ?? '–'}</td>
      <td className="py-1.5 pr-3 text-xs whitespace-nowrap">{formatUtc(node.ts)}</td>
      <td className="py-1.5 pr-3">
        <KindChip kind={node.kind} />
      </td>
      <td className="py-1.5">
        <div className="flex flex-wrap gap-1">
          {node.alerts > 0 && (
            <span className={`${chipClass} bg-orange-200 text-orange-900`}>
              {node.alerts} alert{node.alerts === 1 ? '' : 's'}
            </span>
          )}
          {node.flags.map((f) => (
            <span key={f} className={`${chipClass} bg-red-100 text-red-900`}>
              &#9888; {FLAG_TEXT[f] ?? f}
            </span>
          ))}
        </div>
      </td>
    </tr>
  )
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-slate-200 px-3 py-2 dark:border-slate-800">
      <div className="text-lg font-semibold">{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  )
}

/** Keys of the nodes to show: matching nodes plus every ancestor, so the tree stays connected. */
function visibleKeys(nodes: ProcessNode[], match: (n: ProcessNode) => boolean): Set<string> {
  const byKey = new Map(nodes.map((n) => [n.key, n]))
  const keep = new Set<string>()
  for (const n of nodes) {
    if (!match(n)) continue
    let cur: ProcessNode | undefined = n
    while (cur && !keep.has(cur.key)) {
      keep.add(cur.key)
      cur = cur.parent ? byKey.get(cur.parent) : undefined
    }
  }
  return keep
}

function Tree({ nodes, host }: { nodes: ProcessNode[]; host: string }) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const [alertsOnly, setAlertsOnly] = useState(false)
  const [search, setSearch] = useState('')

  const rows = useMemo(() => {
    const term = search.trim().toLowerCase()
    const filtering = alertsOnly || term !== ''
    const keep = filtering
      ? visibleKeys(nodes, (n) => {
          if (alertsOnly && n.alerts === 0 && n.flags.length === 0) return false
          if (!term) return true
          return [n.name, n.user, n.cmdline, n.pid?.toString()].some((v) => v?.toLowerCase().includes(term))
        })
      : null
    // Pre-order list: a node is hidden when its parent is hidden or collapsed.
    const hidden = new Set<string>()
    const out: ProcessNode[] = []
    for (const n of nodes) {
      const parentHides = n.parent !== null && (hidden.has(n.parent) || collapsed.has(n.parent))
      if (parentHides || (keep && !keep.has(n.key))) {
        hidden.add(n.key)
        continue
      }
      out.push(n)
    }
    return out
  }, [nodes, collapsed, alertsOnly, search])

  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  const parents = nodes.filter((n) => n.children > 0)

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <input
          className={`${inputClass} w-64`}
          type="search"
          aria-label="Filter processes"
          placeholder="Filter by name, user, pid, command…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <label className="inline-flex items-center gap-2 text-sm">
          <input type="checkbox" checked={alertsOnly} onChange={(e) => setAlertsOnly(e.target.checked)} />
          Only processes with alerts or warnings
        </label>
        {parents.length > 0 && (
          <div className="flex gap-2 sm:ml-auto">
            <Button variant="ghost" onClick={() => setCollapsed(new Set())}>
              Expand all
            </Button>
            <Button variant="ghost" onClick={() => setCollapsed(new Set(parents.map((n) => n.key)))}>
              Collapse all
            </Button>
          </div>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm" aria-label={`Processes on ${host}`}>
          <thead className="text-xs text-slate-500 uppercase">
            <tr>
              <th scope="col" className="py-2 pr-3">Process</th>
              <th scope="col" className="pr-3">PID</th>
              <th scope="col" className="pr-3">Parent PID</th>
              <th scope="col" className="pr-3">User</th>
              <th scope="col" className="pr-3">First seen (UTC)</th>
              <th scope="col" className="pr-3">Source</th>
              <th scope="col">Alerts</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((n) => (
              <NodeRow key={n.key} node={n} collapsed={collapsed.has(n.key)} onToggle={() => toggle(n.key)} />
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan={7} className="py-3 text-slate-500">
                  No processes match the filter.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-slate-500">
        Showing {rows.length} of {nodes.length}. Source: <strong>created</strong> = seen starting,{' '}
        <strong>observed</strong> = only seen in later events, <strong>inferred parent</strong> = known only from a
        child&apos;s parent pid. Highlighted rows have alerts or warnings.
      </p>
    </div>
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
  const knownHosts = hosts.data?.fields.host ?? []
  function submit(e: FormEvent) {
    e.preventDefault()
    setHost(draft.trim())
  }
  function pick(h: string) {
    setDraft(h)
    setHost(h)
  }
  const nodes = tree.data?.nodes ?? []
  return (
    <Panel title="Process tree">
      <p className="mb-4 text-sm text-slate-600 dark:text-slate-400">
        Parent and child processes on one host, rebuilt from the case&apos;s events. Pick a host to start.
      </p>
      <form onSubmit={submit} className="mb-4 flex flex-wrap items-end gap-3" aria-label="Choose host">
        <label className="flex flex-col gap-1 text-sm">
          <span className="font-medium">Host</span>
          <input className={`${inputClass} w-64`} list="proc-hosts" value={draft} maxLength={255} onChange={(e) => setDraft(e.target.value)} />
          <datalist id="proc-hosts">
            {knownHosts.map((h) => (
              <option key={h.value} value={h.value} />
            ))}
          </datalist>
        </label>
        <Button type="submit" variant="primary" disabled={!draft.trim()}>
          Show
        </Button>
        {knownHosts.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="text-slate-500">Hosts in this case:</span>
            {knownHosts.map((h) => (
              <Button key={h.value} variant={h.value === host ? 'primary' : 'secondary'} onClick={() => pick(h.value)}>
                {h.value} <span className="text-xs opacity-70">({h.count})</span>
              </Button>
            ))}
          </div>
        )}
      </form>
      {tree.isFetching && <Loading />}
      <ErrorMessage error={tree.error} />
      {tree.data && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Processes" value={nodes.length} />
            <Stat label="Top-level processes" value={tree.data.roots.length} />
            <Stat label="With alerts" value={nodes.filter((n) => n.alerts > 0).length} />
            <Stat label="Warnings" value={nodes.filter((n) => n.flags.length > 0).length} />
          </div>
          {(tree.data.truncated || tree.data.cycles_broken > 0 || tree.data.depth_capped > 0) && (
            <p className="text-xs text-amber-800 dark:text-amber-300">
              {tree.data.truncated && 'Truncated at the node cap. '}
              {tree.data.cycles_broken > 0 && `${tree.data.cycles_broken} parent cycle(s) refused. `}
              {tree.data.depth_capped > 0 && `${tree.data.depth_capped} below the depth cap hidden.`}
            </p>
          )}
          {/* keyed by host so filters and collapsed branches reset when the host changes */}
          <Tree key={tree.data.host} nodes={nodes} host={tree.data.host} />
        </div>
      )}
    </Panel>
  )
}
