/** Per-type colours shared by the entity list, detail pane and graph. */
export const TYPE_ORDER = ['user', 'host', 'process', 'ip', 'domain', 'hash', 'file']

const STYLE: Record<string, { fill: string; text: string; dot: string }> = {
  host: { fill: 'fill-sky-500', text: 'text-sky-700 dark:text-sky-300', dot: 'bg-sky-500' },
  user: { fill: 'fill-emerald-500', text: 'text-emerald-700 dark:text-emerald-300', dot: 'bg-emerald-500' },
  ip: { fill: 'fill-amber-500', text: 'text-amber-700 dark:text-amber-300', dot: 'bg-amber-500' },
  process: { fill: 'fill-violet-500', text: 'text-violet-700 dark:text-violet-300', dot: 'bg-violet-500' },
  domain: { fill: 'fill-rose-500', text: 'text-rose-700 dark:text-rose-300', dot: 'bg-rose-500' },
  hash: { fill: 'fill-slate-500', text: 'text-slate-600 dark:text-slate-300', dot: 'bg-slate-500' },
  file: { fill: 'fill-teal-500', text: 'text-teal-700 dark:text-teal-300', dot: 'bg-teal-500' },
}
const FALLBACK = { fill: 'fill-slate-400', text: 'text-slate-600 dark:text-slate-300', dot: 'bg-slate-400' }

export function typeStyle(type: string) {
  return STYLE[type] ?? FALLBACK
}
