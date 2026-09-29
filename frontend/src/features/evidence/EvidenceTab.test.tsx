import { screen } from '@testing-library/react'

import { EvidenceTab } from '@/features/evidence/EvidenceTab'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch } from '@/test/utils'

const base = {
  case_id: CASE_ID,
  size_bytes: 10,
  sha256: 'a'.repeat(64),
  md5: null,
  status: 'stored',
  source_host: 'web01',
  acquired_at: null,
  created_at: '2026-09-30T08:00:00Z',
}

describe('triage bundles in the evidence list', () => {
  it('offers "Ingest bundle" and shows derived items with their parent', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({
        [`GET /api/v1/cases/${CASE_ID}/evidence`]: () =>
          jsonResponse(200, {
            items: [
              { ...base, id: 'b1', label: 'EV-001', kind: 'triage_bundle', original_name: 'triage_web01.zip', parent_evidence_id: null },
              { ...base, id: 'd1', label: 'EV-001.0001', kind: 'log', original_name: 'logs/var/log/auth.log', parent_evidence_id: 'b1' },
            ],
            total: 2,
          }),
        [`GET /api/v1/cases/${CASE_ID}/jobs`]: () => jsonResponse(200, { items: [], total: 0 }),
      }),
    )
    renderInCase(<EvidenceTab />, ANALYST)
    expect(await screen.findByText('logs/var/log/auth.log')).toBeInTheDocument()
    expect(screen.getByText('from EV-001')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Ingest bundle' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Process' })).toBeInTheDocument()
  })
})
