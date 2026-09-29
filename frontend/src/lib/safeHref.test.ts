import { safeHref } from './safeHref'

describe('safeHref', () => {
  it.each(['https://example.org/a?b=c', 'http://10.0.0.1/', 'mailto:soc@example.org'])('allows %s', (u) => {
    expect(safeHref(u)).not.toBeNull()
  })

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    ' javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
    '//evil.example/',
    '/relative',
    'not a url',
    '',
    null,
    undefined,
  ])('rejects %s', (u) => {
    expect(safeHref(u)).toBeNull()
  })
})
