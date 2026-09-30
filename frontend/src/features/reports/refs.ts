import type { ReportFinding } from '@/api/types'

const REF_LINE = /^(event|alert|evidence)[\s:]+([0-9a-fA-F-]{36})$/

export function refsToText(refs: ReportFinding['refs']): string {
  return refs.map((r) => `${r.type} ${r.id}`).join('\n')
}

/** "event <uuid>" per line -> refs; returns an error message for a bad line. */
export function parseRefs(text: string): { refs: ReportFinding['refs']; error: string | null } {
  const refs: ReportFinding['refs'] = []
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    if (!line) continue
    const m = REF_LINE.exec(line)
    if (!m) return { refs, error: `Not a reference: "${line.slice(0, 60)}" (use: event|alert|evidence <id>)` }
    refs.push({ type: m[1] as 'event' | 'alert' | 'evidence', id: m[2]!.toLowerCase() })
  }
  return { refs, error: null }
}
