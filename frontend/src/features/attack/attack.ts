import type { AttackRow } from '@/api/types'

// Enterprise tactics in kill-chain order (guide 12.5).
export const TACTICS = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
]

export const HEAT = ['bg-amber-100', 'bg-amber-200', 'bg-orange-300', 'bg-red-300']

export function groupByTactic(rows: AttackRow[]): Map<string, AttackRow[]> {
  const out = new Map<string, AttackRow[]>()
  for (const row of rows) {
    const tactics = row.tactics.length ? row.tactics : ['unmapped']
    for (const t of tactics) out.set(t, [...(out.get(t) ?? []), row])
  }
  return out
}
