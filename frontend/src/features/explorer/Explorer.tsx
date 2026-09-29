import { useInfiniteQuery, useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'

import { ApiError } from '@/api/client'
import { api, type QueryScope } from '@/api/endpoints'
import type { EventRow } from '@/api/types'
import { caseHref, navigate, useLocation } from '@/app/router'
import { Button, ErrorMessage, Loading, Panel } from '@/components/ui'
import { useCase } from '@/features/cases/CaseContext'
import { addFilter } from '@/lib/searchLanguage'

import { EventDrawer } from './EventDrawer'
import { EventTable } from './EventTable'
import { FacetPanel } from './FacetPanel'
import { Histogram } from './Histogram'
import { QueryBar, type QueryState } from './QueryBar'

const FACETS = ['host', 'user', 'source_type', 'event_code', 'attack_tags', 'src_ip']

function serverQueryError(err: unknown): { message: string; position?: number } | null {
  if (err instanceof ApiError && err.code === 'invalid_query') {
    const pos = err.details.position
    return { message: err.message, position: typeof pos === 'number' ? pos : undefined }
  }
  return null
}

/** Timeline Explorer (guide 12.1, 17.3). The URL holds query and range (shareable links). */
export function Explorer() {
  const { caseId, can } = useCase()
  const { params } = useLocation()
  const state: QueryState = { q: params.get('q') ?? '', from: params.get('from') ?? '', to: params.get('to') ?? '' }
  const scope: QueryScope = { query: state.q, from: state.from || undefined, to: state.to || undefined }
  const key = [caseId, state.q, state.from, state.to]
  const [open, setOpen] = useState<EventRow | null>(null)

  const events = useInfiniteQuery({
    queryKey: ['search', ...key],
    queryFn: ({ pageParam, signal }) => api.search(caseId, scope, pageParam, signal),
    initialPageParam: null as string | null,
    getNextPageParam: (last) => last.next_cursor,
    retry: false,
  })
  const histogram = useQuery({
    queryKey: ['histogram', ...key],
    queryFn: ({ signal }) => api.histogram(caseId, scope, signal),
    retry: false,
  })
  const facets = useQuery({
    queryKey: ['facets', ...key],
    queryFn: ({ signal }) => api.facets(caseId, scope, FACETS, signal),
    retry: false,
  })
  const exporter = useMutation({
    mutationFn: async (format: 'csv' | 'json') => {
      const blob = await api.exportEvents(caseId, scope, format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `events.${format}`
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    },
  })

  function go(next: QueryState) {
    const p: Record<string, string> = {}
    if (next.q) p.q = next.q
    if (next.from) p.from = next.from
    if (next.to) p.to = next.to
    navigate(caseHref(caseId, 'timeline', p))
  }

  const rows = events.data?.pages.flatMap((p) => p.items) ?? []
  const queryError = serverQueryError(events.error)

  return (
    <div className="space-y-3">
      <Panel
        title="Timeline explorer"
        actions={
          can('investigate') && (
            <div className="flex gap-1">
              <Button onClick={() => exporter.mutate('csv')} disabled={exporter.isPending}>
                Export CSV
              </Button>
              <Button onClick={() => exporter.mutate('json')} disabled={exporter.isPending}>
                Export JSON
              </Button>
            </div>
          )
        }
      >
        <QueryBar key={key.join('|')} initial={state} serverError={queryError} onSubmit={go} />
        <ErrorMessage error={exporter.error} />
        <div className="mt-3">
          {histogram.data && (
            <Histogram data={histogram.data} onZoom={(from, to) => go({ ...state, from, to })} />
          )}
        </div>
      </Panel>
      <div className="grid gap-3 lg:grid-cols-[14rem_1fr]">
        <Panel title="Facets">
          {facets.data ? (
            <FacetPanel
              facets={facets.data.fields}
              onPick={(field, value, negate) => go({ ...state, q: addFilter(state.q, field, value, negate) })}
            />
          ) : (
            facets.isPending && <Loading />
          )}
        </Panel>
        <Panel title="Events">
          {events.isPending && <Loading />}
          {!queryError && <ErrorMessage error={events.error} />}
          {events.data && <EventTable events={rows} onOpen={setOpen} />}
          {events.hasNextPage && (
            <Button className="mt-2" onClick={() => void events.fetchNextPage()} disabled={events.isFetchingNextPage}>
              {events.isFetchingNextPage ? 'Loading…' : 'Load more'}
            </Button>
          )}
        </Panel>
      </div>
      {open && (
        <EventDrawer
          event={open}
          onClose={() => setOpen(null)}
          onPivot={(field, value) => {
            setOpen(null)
            go({ ...state, q: addFilter(state.q, field, value) })
          }}
        />
      )}
    </div>
  )
}
