import { fireEvent, screen } from '@testing-library/react'

import { Dialog } from '@/components/Dialog'
import { EvidenceTab } from '@/features/evidence/EvidenceTab'
import { NotesTab } from '@/features/notes/NotesTab'
import { ANALYST, CASE_ID, jsonResponse, renderInCase, routeFetch, VIEWER } from '@/test/utils'

const EVIDENCE = {
  items: [
    {
      id: 'e1',
      case_id: CASE_ID,
      label: 'EV-001',
      kind: 'log',
      original_name: 'auth.log',
      size_bytes: 10,
      sha256: 'a'.repeat(64),
      md5: null,
      status: 'stored',
      source_host: null,
      acquired_at: null,
      created_at: '2026-09-14T08:00:00Z',
    },
  ],
  total: 1,
}

function mockApi() {
  vi.stubGlobal(
    'fetch',
    routeFetch({
      [`GET /api/v1/cases/${CASE_ID}/evidence`]: () => jsonResponse(200, EVIDENCE),
      [`GET /api/v1/cases/${CASE_ID}/jobs`]: () => jsonResponse(200, { items: [], total: 0 }),
      [`GET /api/v1/cases/${CASE_ID}/notes`]: () =>
        jsonResponse(200, {
          items: [
            {
              id: 'n1',
              case_id: CASE_ID,
              author_id: 'someone-else',
              target_type: 'case',
              target_id: CASE_ID,
              body_md: '<script>alert(1)</script>',
              tags: [],
              version: 1,
              created_at: '2026-09-14T08:00:00Z',
              updated_at: '2026-09-14T08:00:00Z',
              retracted_at: null,
            },
          ],
          total: 1,
        }),
      [`GET /api/v1/cases/${CASE_ID}/bookmarks`]: () => jsonResponse(200, []),
    }),
  )
}

describe('RBAC-hidden actions (the server still enforces them)', () => {
  it('a viewer sees evidence but no verify/process/upload actions', async () => {
    mockApi()
    renderInCase(<EvidenceTab />, VIEWER)
    expect(await screen.findByText('auth.log')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Verify' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Process' })).toBeNull()
    expect(screen.queryByRole('form', { name: 'Upload evidence' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Custody chain/ })).toBeNull()
  })

  it('an analyst sees the actions', async () => {
    mockApi()
    renderInCase(<EvidenceTab />, ANALYST)
    expect(await screen.findByRole('button', { name: 'Verify' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Process' })).toBeInTheDocument()
    expect(screen.getByRole('form', { name: 'Upload evidence' })).toBeInTheDocument()
  })

  it('closed cases hide write actions even for analysts', async () => {
    mockApi()
    renderInCase(<EvidenceTab />, ANALYST, 'closed')
    expect(await screen.findByText('auth.log')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Process' })).toBeNull()
    expect(screen.getByRole('button', { name: /Custody chain/ })).toBeInTheDocument()
  })

  it('notes: viewers cannot add, others cannot edit; bodies render as text', async () => {
    mockApi()
    renderInCase(<NotesTab />, VIEWER)
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(screen.queryByRole('form', { name: 'Add a case note' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Retract' })).toBeNull()
    expect(document.querySelector('script')).toBeNull()
  })

  it('notes: analysts can add but not edit another author’s note', async () => {
    mockApi()
    renderInCase(<NotesTab />, ANALYST)
    expect(await screen.findByRole('form', { name: 'Add a case note' })).toBeInTheDocument()
    expect(await screen.findByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit' })).toBeNull()
  })
})

describe('Dialog', () => {
  it('is labelled, takes focus and closes on Escape', () => {
    const onClose = vi.fn()
    renderInCase(
      <Dialog title="Details" onClose={onClose}>
        <button type="button">inside</button>
      </Dialog>,
      VIEWER,
    )
    const dialog = screen.getByRole('dialog', { name: 'Details' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog.contains(document.activeElement)).toBe(true)
    fireEvent.keyDown(dialog, { key: 'Escape' })
    expect(onClose).toHaveBeenCalled()
  })
})
