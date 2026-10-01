import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from '@/api/endpoints'
import type { AppNotification } from '@/api/types'
import { caseHref } from '@/app/router'
import { Link } from '@/app/Link'
import { Button, ErrorMessage, Loading, Panel } from '@/components/ui'
import { formatUtc } from '@/lib/format'

const TABS = new Set(['overview', 'alerts', 'evidence', 'reports', 'response'])
const UUID = /^[0-9a-fA-F-]{36}$/

/** A same-origin case link built from validated parts (never from a URL in the payload). */
function target(n: AppNotification): string | null {
  const caseId = n.case_id ?? n.payload.case_id
  if (typeof caseId !== 'string' || !UUID.test(caseId)) return null
  const tab = typeof n.payload.tab === 'string' && TABS.has(n.payload.tab) ? n.payload.tab : 'overview'
  return caseHref(caseId, tab)
}

/** In-app notifications of the signed-in user (guide 19.4). Payloads carry ids and counts only. */
export function NotificationsPage() {
  const client = useQueryClient()
  const q = useQuery({ queryKey: ['notifications'], queryFn: ({ signal }) => api.notifications(signal) })
  const refresh = () => void client.invalidateQueries({ queryKey: ['notifications'] })
  const read = useMutation({ mutationFn: (id: string) => api.readNotification(id), onSuccess: refresh })
  const readAll = useMutation({ mutationFn: () => api.readAllNotifications(), onSuccess: refresh })
  return (
    <Panel
      title="Notifications"
      actions={
        <Button disabled={readAll.isPending || !q.data || q.data.unread === 0} onClick={() => readAll.mutate()}>
          Mark all read
        </Button>
      }
    >
      {q.isPending && <Loading />}
      <ErrorMessage error={q.error ?? read.error ?? readAll.error} />
      {q.data && q.data.items.length === 0 && <p className="text-sm text-slate-500">No notifications.</p>}
      {q.data && <p className="text-sm">{q.data.unread} unread</p>}
      <ul className="mt-2 text-sm">
        {(q.data?.items ?? []).map((n) => {
          const href = target(n)
          const fields = Array.isArray(n.payload.fields) ? n.payload.fields : []
          return (
            <li key={n.id} className="border-t border-slate-200 py-2 dark:border-slate-800">
              <p className={n.read_at ? '' : 'font-semibold'}>
                {typeof n.payload.title === 'string' ? n.payload.title : n.kind}{' '}
                <span className="font-normal text-slate-500">{formatUtc(n.created_at)}</span>
              </p>
              <p className="text-xs text-slate-600 dark:text-slate-400">
                {fields.map((f) => `${String(f.label)}: ${String(f.value)}`).join(' · ')}
              </p>
              <div className="flex items-center gap-3">
                {href && (
                  <Link to={href} className="text-sky-700 hover:underline dark:text-sky-400">
                    Open case
                  </Link>
                )}
                {!n.read_at && (
                  <Button variant="ghost" disabled={read.isPending} onClick={() => read.mutate(n.id)}>
                    Mark read
                  </Button>
                )}
              </div>
            </li>
          )
        })}
      </ul>
    </Panel>
  )
}
