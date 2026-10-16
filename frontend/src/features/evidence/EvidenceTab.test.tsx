import { fireEvent, screen, waitFor } from '@testing-library/react'

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

describe('upload form', () => {
  it('explains the disabled Upload button and enables it once a file is chosen', async () => {
    vi.stubGlobal(
      'fetch',
      routeFetch({
        [`GET /api/v1/cases/${CASE_ID}/evidence`]: () => jsonResponse(200, { items: [], total: 0 }),
        [`GET /api/v1/cases/${CASE_ID}/jobs`]: () => jsonResponse(200, { items: [], total: 0 }),
      }),
    )
    renderInCase(<EvidenceTab />, ANALYST)
    const upload = await screen.findByRole('button', { name: 'Upload' })
    expect(upload).toBeDisabled()
    expect(upload).toHaveAttribute('title', 'Choose a file first')
    expect(screen.getByText('Choose a file to enable Upload.')).toBeInTheDocument()
    const picker = screen.getByLabelText('File')
    fireEvent.change(picker, { target: { files: [new File(['x'], 'Security.evtx')] } })
    await waitFor(() => expect(upload).toBeEnabled())
  })
})

describe('automatic file type detection', () => {
  it('detects the kind, uploads with it and starts processing', async () => {
    const calls: string[] = []
    const stored = { ...base, id: 'e1', label: 'EV-001', kind: 'evtx', original_name: 'Security.evtx', parent_evidence_id: null }
    const fetchMock = routeFetch({
      [`GET /api/v1/cases/${CASE_ID}/evidence`]: () => jsonResponse(200, { items: [], total: 0 }),
      [`GET /api/v1/cases/${CASE_ID}/jobs`]: () => jsonResponse(200, { items: [], total: 0 }),
      [`POST /api/v1/cases/${CASE_ID}/evidence/identify`]: () =>
        jsonResponse(200, { kind: 'evtx', parser: 'evtx', confidence: 0.95, description: 'Windows event log' }),
      [`POST /api/v1/cases/${CASE_ID}/evidence`]: (init) => {
        calls.push(`create ${JSON.parse(String(init.body)).kind}`)
        return jsonResponse(201, { evidence: { ...stored, status: 'uploading' } })
      },
      'PUT /api/v1/evidence/e1/upload': () => jsonResponse(200, stored),
      'POST /api/v1/evidence/e1/finalize': () => jsonResponse(200, { ok: true, evidence: stored }),
      'POST /api/v1/evidence/e1/process': () => {
        calls.push('process')
        return jsonResponse(202, { jobs: [] })
      },
    })
    vi.stubGlobal('fetch', fetchMock)
    renderInCase(<EvidenceTab />, ANALYST)
    const picker = await screen.findByLabelText('File')
    fireEvent.change(picker, { target: { files: [new File(['ElfFile\0'], 'Security.evtx')] } })
    expect(await screen.findByText('Windows event log')).toBeInTheDocument()
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument() // no kind to pick by hand
    const upload = screen.getByRole('button', { name: 'Upload' })
    await waitFor(() => expect(upload).toBeEnabled())
    fireEvent.click(upload)
    expect(await screen.findByText(/Processing started/)).toBeInTheDocument()
    expect(calls).toEqual(['create evtx', 'process'])
  })
})
