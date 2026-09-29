import type { FacetValue } from '@/api/types'

export function FacetPanel({
  facets,
  onPick,
}: {
  facets: Record<string, FacetValue[]>
  onPick: (field: string, value: string, negate: boolean) => void
}) {
  return (
    <nav aria-label="Facets" className="space-y-3 text-sm">
      {Object.entries(facets).map(([field, values]) => (
        <section key={field} aria-labelledby={`facet-${field}`}>
          <h3 id={`facet-${field}`} className="text-xs font-semibold text-slate-500 uppercase">
            {field}
          </h3>
          {values.length === 0 && <p className="text-xs text-slate-400">none</p>}
          <ul>
            {values.map((v) => (
              <li key={v.value} className="flex items-center gap-1">
                <button
                  type="button"
                  className="min-w-0 flex-1 truncate text-left text-sky-700 hover:underline dark:text-sky-400"
                  title={v.value}
                  onClick={() => onPick(field, v.value, false)}
                >
                  {v.value}
                </button>
                <span className="text-xs text-slate-500">{v.count}</span>
                <button
                  type="button"
                  className="px-1 text-xs text-slate-500 hover:text-red-700"
                  aria-label={`Exclude ${field} ${v.value}`}
                  onClick={() => onPick(field, v.value, true)}
                >
                  &minus;
                </button>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </nav>
  )
}
