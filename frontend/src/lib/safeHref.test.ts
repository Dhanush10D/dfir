import { isSameOriginPath, safeHref, trimControl } from './safeHref'

describe('safeHref', () => {
  it.each([
    ['https://example.org/a?b=c', 'https://example.org/a?b=c'],
    ['http://10.0.0.1/', 'http://10.0.0.1/'],
    ['mailto:soc@example.org', 'mailto:soc@example.org'],
    ['HTTPS://Example.org/', 'https://example.org/'],
    ['  https://example.org/x\n', 'https://example.org/x'],
    ['\u0001\u0000https://example.org/\u007f', 'https://example.org/'],
  ])('allows %j', (input, expected) => {
    expect(safeHref(input)).toBe(expected)
  })

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    ' javascript:alert(1)',
    '\u0000javascript:alert(1)',
    '\u0001 JAVASCRIPT:alert(1)',
    ' javascript:alert(1)',
    '﻿javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'java\rscript:alert(1)',
    'java\u0000script:alert(1)',
    'javascript&colon;alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'DATA:text/html;base64,PHNjcmlwdD4=',
    'vbscript:msgbox(1)',
    'VBScript:msgbox(1)',
    'file:///etc/passwd',
    '//evil.example/',
    '\\\\evil.example/',
    '/\\evil.example/',
    'https:',
    '/relative',
    'relative/path',
    'not a url',
    'https://exa mple.org/',
    '',
    '   ',
    null,
    undefined,
  ])('rejects %j', (u) => {
    expect(safeHref(u)).toBeNull()
  })
})

describe('isSameOriginPath', () => {
  it.each(['/cases', '/cases/abc/explorer?q=host%3Ax'])('accepts %j', (p) => {
    expect(isSameOriginPath(p)).toBe(true)
  })

  it.each(['//evil.example', '/\\evil.example', '\\\\evil.example', 'https://x', 'javascript:x', '/a\nb', ''])(
    'rejects %j',
    (p) => {
      expect(isSameOriginPath(p)).toBe(false)
    },
  )
})

describe('trimControl', () => {
  it('trims whitespace and control characters at both ends only', () => {
    expect(trimControl('\u0000\t a b \u007f\n')).toBe('a b')
  })
})
