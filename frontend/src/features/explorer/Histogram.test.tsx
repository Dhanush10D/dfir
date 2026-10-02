import { fireEvent, render, screen } from '@testing-library/react'

import { Histogram } from './Histogram'

test('zooming into a bar covers the whole bucket, down to its last microsecond', () => {
  const onZoom = vi.fn()
  render(
    <Histogram
      data={{
        interval_seconds: 60,
        from: null,
        to: null,
        buckets: [{ ts: '2026-09-14T08:00:00Z', count: 3, by: {} }],
        series: [],
        total: 3,
      }}
      onZoom={onZoom}
    />,
  )
  fireEvent.click(screen.getByRole('button', { name: /Zoom in/ }))
  expect(onZoom).toHaveBeenCalledWith('2026-09-14T08:00:00.000Z', '2026-09-14T08:00:59.999999Z')
})
