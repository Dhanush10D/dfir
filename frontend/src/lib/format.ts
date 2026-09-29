/** Display helpers. Timestamps are always shown in UTC (guide 10.5). */

export function formatUtc(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z')
}

export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return '-'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function shortHash(h: string | null | undefined, n = 12): string {
  return h ? `${h.slice(0, n)}…` : '-'
}

export function errorText(err: unknown): string {
  if (err instanceof Error) return err.message
  return 'Unexpected error'
}
