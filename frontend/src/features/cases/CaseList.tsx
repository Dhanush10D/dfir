import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'

import { api } from '@/api/endpoints'
import { caseHref, navigate } from '@/app/router'
import { Link } from '@/app/Link'
import { useAuth } from '@/auth/AuthContext'
import { Button, ErrorMessage, inputClass, Loading, Panel, SeverityChip } from '@/components/ui'
import { formatUtc } from '@/lib/format'

export function CaseList() {
  const { can } = useAuth()
  const client = useQueryClient()
  const cases = useQuery({ queryKey: ['cases'], queryFn: ({ signal }) => api.cases(signal) })
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const create = useMutation({
    mutationFn: () => api.createCase(title.trim(), description.trim()),
    onSuccess: (c) => {
      void client.invalidateQueries({ queryKey: ['cases'] })
      navigate(caseHref(c.id, 'overview'))
    },
  })

  function submit(e: FormEvent) {
    e.preventDefault()
    if (title.trim()) create.mutate()
  }

  return (
    <div className="space-y-4">
      <Panel title="Cases">
        {cases.isPending && <Loading />}
        <ErrorMessage error={cases.error} />
        {cases.data && (
          <table className="w-full text-left text-sm">
            <caption className="sr-only">Cases you can access</caption>
            <thead className="text-xs text-slate-500 uppercase">
              <tr>
                <th scope="col" className="py-1">Case</th>
                <th scope="col">Title</th>
                <th scope="col">Status</th>
                <th scope="col">Severity</th>
                <th scope="col">Opened (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {cases.data.items.map((c) => (
                <tr key={c.id} className="border-t border-slate-100 dark:border-slate-800">
                  <td className="py-1.5 font-mono">
                    <Link to={caseHref(c.id, 'overview')} className="text-sky-700 hover:underline dark:text-sky-400">
                      {c.case_number}
                    </Link>
                  </td>
                  <td>{c.title}</td>
                  <td>{c.status}</td>
                  <td>
                    <SeverityChip severity={c.severity} />
                  </td>
                  <td>{formatUtc(c.opened_at)}</td>
                </tr>
              ))}
              {cases.data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-2 text-slate-500">
                    No cases yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </Panel>
      {can('case:create') && (
        <Panel title="New case">
          <form onSubmit={submit} className="flex flex-wrap items-end gap-2" aria-label="Create a case">
            <label className="text-sm">
              <span className="mb-1 block font-medium">Title</span>
              <input className={inputClass} required maxLength={300} value={title} onChange={(e) => setTitle(e.target.value)} />
            </label>
            <label className="text-sm">
              <span className="mb-1 block font-medium">Description</span>
              <input className={inputClass} maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
            </label>
            <Button type="submit" variant="primary" disabled={create.isPending}>
              Create
            </Button>
            <ErrorMessage error={create.error} />
          </form>
        </Panel>
      )}
    </div>
  )
}
