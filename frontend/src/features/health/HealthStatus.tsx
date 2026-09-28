import { useHealth } from '@/api/health'

/** API liveness indicator. Status is shown as text + icon, never color alone (guide 17.4). */
export function HealthStatus() {
  const { data, error, isPending } = useHealth()

  if (isPending) {
    return (
      <p role="status" className="text-sm text-slate-500">
        Checking API...
      </p>
    )
  }

  if (error) {
    return (
      <p role="status" className="text-sm font-medium text-red-700 dark:text-red-400">
        <span aria-hidden="true">&#x2715; </span>API unreachable: {error.message}
      </p>
    )
  }

  return (
    <dl
      role="status"
      aria-label="API status"
      className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm"
    >
      <dt className="text-slate-500">API</dt>
      <dd className="font-medium text-emerald-700 dark:text-emerald-400">
        <span aria-hidden="true">&#x2713; </span>
        {data.status}
      </dd>
      <dt className="text-slate-500">Version</dt>
      <dd>{data.version}</dd>
      <dt className="text-slate-500">Environment</dt>
      <dd>{data.env}</dd>
      <dt className="text-slate-500">Server time (UTC)</dt>
      <dd>
        <time dateTime={data.time}>{data.time}</time>
      </dd>
    </dl>
  )
}
