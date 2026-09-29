import { addFilter, quoteValue, validateQuery } from './searchLanguage'

describe('search language (client mirror)', () => {
  it.each([
    '',
    'event_code:4625 AND src_ip:203.0.113.0/24',
    'host:WS-042 AND process_name:powershell.exe AND cmdline:*-enc*',
    'ts:[2026-09-01T00:00:00Z TO 2026-09-02T00:00:00Z] AND NOT user:SYSTEM',
    'attack_tags:T1059.001 OR attack_tags:T1059*',
    '"failed password" (host:a OR host:b) pid:[1 TO *]',
    'file_path:"C:\\\\Windows\\\\x"',
    'user:*',
  ])('accepts %s', (q) => {
    expect(validateQuery(q)).toBeNull()
  })

  it.each([
    ['host:', 5],
    ['nosuch:x', 0],
    ['host:a AND', 10],
    ['AND host:a', 0],
    ['(host:a', 0],
    ['host:a)', 6],
    ['"unterminated', 0],
    ['cmdline:*ab', 8],
    ['pid:abc', 4],
    ['ts:2026-01-01', 3],
    ['ts:[2026-01-01T00:00:00 TO *]', 3],
    ['host:[a TO b]', 5],
    ['attack_tags:X1', 12],
    ['mimi*', 0],
  ] as const)('rejects %s at %i', (q, pos) => {
    const err = validateQuery(q)
    expect(err).not.toBeNull()
    expect(err?.position).toBe(pos)
  })

  it('enforces the caps', () => {
    expect(validateQuery('a'.repeat(2001))?.message).toMatch(/too long/)
    expect(validateQuery('('.repeat(13) + 'a' + ')'.repeat(13))?.message).toMatch(/nested/)
    expect(validateQuery(Array(41).fill('a').join(' '))?.message).toMatch(/Too many terms/)
  })

  it('quotes values and builds filters safely', () => {
    expect(quoteValue('a"b\\c')).toBe('"a\\"b\\\\c"')
    expect(addFilter('', 'host', 'WS-042')).toBe('host:"WS-042"')
    expect(addFilter('user:x', 'host', 'h', true)).toBe('user:x AND NOT host:"h"')
    expect(addFilter('a OR b', 'host', 'h')).toBe('(a OR b) AND host:"h"')
    const hostile = '" OR host:* OR "'
    const q = addFilter('', 'user', hostile)
    expect(validateQuery(q)).toBeNull()
    expect(q).toBe('user:"\\" OR host:* OR \\""')
  })
})
