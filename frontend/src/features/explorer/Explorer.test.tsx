import { fireEvent, render, screen } from '@testing-library/react'

import type { EventRow } from '@/api/types'
import { Link } from '@/app/Link'

import { EventTable } from './EventTable'
import { QueryBar } from './QueryBar'

function event(overrides: Partial<EventRow>): EventRow {
  return {
    id: crypto.randomUUID(),
    case_id: 'c',
    evidence_id: null,
    ts: '2026-09-14T08:00:00Z',
    ts_original: null,
    source_type: 'evtx',
    source_file: null,
    source_record_id: null,
    host: 'WS-042',
    user: 'CORP\\alice',
    event_code: '4688',
    event_category: 'process',
    action: 'create',
    outcome: 'success',
    process_name: 'cmd.exe',
    pid: 1,
    ppid: 2,
    cmdline: null,
    file_path: null,
    file_hash: null,
    src_ip: null,
    dst_ip: null,
    src_port: null,
    dst_port: null,
    protocol: null,
    registry_key: null,
    message: 'ok',
    attack_tags: [],
    tags: [],
    parser_name: 'evtx',
    ...overrides,
  }
}

describe('EventTable', () => {
  it('renders hostile evidence strings as text, never as HTML', () => {
    const hostile = '<img src=x onerror=alert(1)><script>alert(2)</script>'
    const { container } = render(
      <EventTable
        events={[event({ message: hostile, host: '<b>bold</b>', user: '"><svg onload=alert(3)>' })]}
        onOpen={() => {}}
      />,
    )
    expect(screen.getByText(hostile)).toBeInTheDocument()
    expect(screen.getByText('<b>bold</b>')).toBeInTheDocument()
    expect(container.querySelector('img, script, svg, b')).toBeNull()
  })

  it('supports keyboard navigation and Enter to open', () => {
    const onOpen = vi.fn()
    const rows = [event({ message: 'first' }), event({ message: 'second' })]
    render(<EventTable events={rows} onOpen={onOpen} />)
    const first = screen.getByText('first').closest('tr') as HTMLElement
    const second = screen.getByText('second').closest('tr') as HTMLElement
    expect(first.tabIndex).toBe(0)
    expect(second.tabIndex).toBe(-1)
    first.focus()
    fireEvent.keyDown(first, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(second)
    fireEvent.keyDown(second, { key: 'Enter' })
    expect(onOpen).toHaveBeenCalledWith(rows[1])
  })
})

describe('QueryBar', () => {
  it('shows parse errors with their position and does not submit', () => {
    const onSubmit = vi.fn()
    render(<QueryBar initial={{ q: '', from: '', to: '' }} onSubmit={onSubmit} />)
    const input = screen.getByLabelText('Query')
    fireEvent.change(input, { target: { value: 'host:a AND' } })
    fireEvent.click(screen.getByRole('button', { name: 'Run' }))
    expect(screen.getByRole('alert')).toHaveTextContent(/term is missing.*character 11/)
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(onSubmit).not.toHaveBeenCalled()

    fireEvent.change(input, { target: { value: 'host:a AND user:b' } })
    fireEvent.click(screen.getByRole('button', { name: 'Run' }))
    expect(onSubmit).toHaveBeenCalledWith({ q: 'host:a AND user:b', from: '', to: '' })
  })

  it('shows the server error for a query the client accepted', () => {
    render(
      <QueryBar
        initial={{ q: 'x', from: '', to: '' }}
        serverError={{ message: 'Query too long.', position: 3 }}
        onSubmit={() => {}}
      />,
    )
    expect(screen.getByRole('alert')).toHaveTextContent('Query too long. (at character 4)')
  })
})

describe('Link', () => {
  it('renders unsafe data URLs as text', () => {
    const { container } = render(<Link to="javascript:alert(1)">x</Link>)
    expect(container.querySelector('a')).toBeNull()
    render(<Link to="https://example.org/">ext</Link>)
    expect(screen.getByText('ext').closest('a')).toHaveAttribute('rel', 'noopener noreferrer nofollow')
  })
})
