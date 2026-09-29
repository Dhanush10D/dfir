/**
 * Client-side mirror of the search language (backend app/search/language.py, guide 12.2).
 * Used only to point at mistakes before a request is sent; the server parser is authoritative.
 */

export const MAX_QUERY = 2000
export const MAX_DEPTH = 12
export const MAX_TERMS = 40
export const MAX_VALUE = 512
export const MAX_WILDCARDS = 4
export const MIN_LEADING_LITERAL = 3

export type FieldKind = 'text' | 'int' | 'ip' | 'ts' | 'array' | 'uuid'

export const FIELDS: Record<string, FieldKind> = {
  host: 'text',
  user: 'text',
  event_code: 'text',
  event_category: 'text',
  action: 'text',
  outcome: 'text',
  source_type: 'text',
  source_file: 'text',
  source_record_id: 'text',
  process_name: 'text',
  cmdline: 'text',
  file_path: 'text',
  file_hash: 'text',
  protocol: 'text',
  registry_key: 'text',
  message: 'text',
  parser_name: 'text',
  pid: 'int',
  ppid: 'int',
  src_port: 'int',
  dst_port: 'int',
  src_ip: 'ip',
  dst_ip: 'ip',
  ip: 'ip',
  ts: 'ts',
  attack_tags: 'array',
  tags: 'array',
  evidence_id: 'uuid',
  job_id: 'uuid',
}

const WILDCARD_KINDS: ReadonlySet<FieldKind> = new Set(['text', 'array'])
const EXISTS_KINDS: ReadonlySet<FieldKind> = new Set(['text', 'int', 'ip', 'array'])
const KEYWORDS = new Set(['AND', 'OR', 'NOT', 'TO'])
const FIELD_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/
const SPECIAL = new Set(['(', ')', '[', ']', '"'])

export class QueryError extends Error {
  readonly position: number
  constructor(message: string, position: number) {
    super(message)
    this.name = 'QueryError'
    this.position = position
  }
}

type Kind = 'word' | 'quoted' | 'field' | 'lparen' | 'rparen' | 'lbrack' | 'rbrack' | 'kw'
interface Token {
  kind: Kind
  text: string
  pos: number
  end: number
  rest: string
}

function isSpace(ch: string): boolean {
  return /\s/.test(ch)
}

export function tokenize(query: string): Token[] {
  const tokens: Token[] = []
  const singles: Record<string, Kind> = { '(': 'lparen', ')': 'rparen', '[': 'lbrack', ']': 'rbrack' }
  let i = 0
  while (i < query.length) {
    const ch = query[i] as string
    if (isSpace(ch)) {
      i += 1
      continue
    }
    const single = singles[ch]
    if (single) {
      tokens.push({ kind: single, text: ch, pos: i, end: i + 1, rest: '' })
      i += 1
      continue
    }
    if (ch === '"') {
      const start = i
      i += 1
      let buf = ''
      for (;;) {
        if (i >= query.length) throw new QueryError('Unterminated quoted string.', start)
        const c = query[i] as string
        const next = query[i + 1]
        if (c === '\\' && next !== undefined && (next === '"' || next === '\\')) {
          buf += next
          i += 2
          continue
        }
        if (c === '"') {
          i += 1
          break
        }
        buf += c
        i += 1
      }
      tokens.push({ kind: 'quoted', text: buf, pos: start, end: i, rest: '' })
      continue
    }
    const start = i
    while (i < query.length && !isSpace(query[i] as string) && !SPECIAL.has(query[i] as string)) {
      i += 1
    }
    const word = query.slice(start, i)
    if (KEYWORDS.has(word)) {
      tokens.push({ kind: 'kw', text: word, pos: start, end: i, rest: '' })
      continue
    }
    const colon = word.indexOf(':')
    const name = colon >= 0 ? word.slice(0, colon) : ''
    if (colon >= 0 && FIELD_RE.test(name)) {
      tokens.push({ kind: 'field', text: name, pos: start, end: i, rest: word.slice(colon + 1) })
    } else {
      tokens.push({ kind: 'word', text: word, pos: start, end: i, rest: '' })
    }
  }
  return tokens
}

function checkValue(value: string, pos: number): void {
  if (value.length > MAX_VALUE) throw new QueryError(`Value too long (at most ${MAX_VALUE} characters).`, pos)
}

function checkTerm(field: string, kind: FieldKind, value: string, quoted: boolean, pos: number): void {
  checkValue(value, pos)
  if (value === '*' && !quoted) {
    if (!EXISTS_KINDS.has(kind)) throw new QueryError(`Field '${field}' does not support '*'.`, pos)
    return
  }
  if (!value) throw new QueryError(`Empty value for '${field}'.`, pos)
  if (kind === 'ts') throw new QueryError('Use a range for time: ts:[2026-01-01T00:00:00Z TO *].', pos)
  const stars = quoted ? 0 : value.split('*').length - 1
  if (stars) {
    if (!WILDCARD_KINDS.has(kind)) throw new QueryError(`Field '${field}' does not support wildcards.`, pos)
    if (stars > MAX_WILDCARDS) throw new QueryError(`At most ${MAX_WILDCARDS} wildcards per value.`, pos)
    if (value.startsWith('*') && value.replaceAll('*', '').length < MIN_LEADING_LITERAL) {
      throw new QueryError(
        `A leading wildcard needs at least ${MIN_LEADING_LITERAL} other characters.`,
        pos,
      )
    }
    return
  }
  if (kind === 'int' && !/^-?[0-9]{1,10}$/.test(value)) {
    throw new QueryError(`'${value.slice(0, 40)}' is not a whole number.`, pos)
  }
  if (field === 'attack_tags' && !/^[Tt][0-9]{4}(\.[0-9]{3})?$/.test(value)) {
    throw new QueryError('ATT&CK ids look like T1059 or T1059.001.', pos)
  }
}

class Parser {
  private i = 0
  private terms = 0
  private readonly tokens: Token[]
  constructor(private readonly query: string) {
    this.tokens = tokenize(query)
  }

  private peek(): Token | undefined {
    return this.tokens[this.i]
  }

  private take(): Token {
    const tok = this.tokens[this.i] as Token
    this.i += 1
    return tok
  }

  private countTerm(pos: number): void {
    this.terms += 1
    if (this.terms > MAX_TERMS) throw new QueryError(`Too many terms (at most ${MAX_TERMS}).`, pos)
  }

  parse(): void {
    this.parseOr(0)
    const tok = this.peek()
    if (tok) {
      if (tok.kind === 'rparen') throw new QueryError("Unbalanced ')'.", tok.pos)
      throw new QueryError(`Unexpected '${tok.text}'.`, tok.pos)
    }
  }

  private parseOr(depth: number): void {
    this.parseAnd(depth)
    for (let tok = this.peek(); tok && tok.kind === 'kw' && tok.text === 'OR'; tok = this.peek()) {
      this.take()
      this.parseAnd(depth)
    }
  }

  private parseAnd(depth: number): void {
    this.parseUnary(depth)
    for (let tok = this.peek(); tok && tok.kind !== 'rparen'; tok = this.peek()) {
      if (tok.kind === 'kw' && tok.text === 'OR') break
      if (tok.kind === 'kw' && tok.text === 'AND') this.take()
      this.parseUnary(depth)
    }
  }

  private parseUnary(depth: number): void {
    const tok = this.peek()
    if (!tok) throw new QueryError('Unexpected end of query: a term is missing.', this.query.length)
    if (depth >= MAX_DEPTH) throw new QueryError(`Query nested too deeply (at most ${MAX_DEPTH}).`, tok.pos)
    if (tok.kind === 'kw') {
      if (tok.text === 'NOT') {
        this.take()
        this.parseUnary(depth + 1)
        return
      }
      if (tok.text === 'TO') throw new QueryError("'TO' is only valid inside a range: field:[a TO b].", tok.pos)
      throw new QueryError(`'${tok.text}' needs a term on both sides.`, tok.pos)
    }
    if (tok.kind === 'lparen') {
      this.take()
      this.parseOr(depth + 1)
      const close = this.peek()
      if (!close || close.kind !== 'rparen') throw new QueryError("Missing ')'.", tok.pos)
      this.take()
      return
    }
    if (tok.kind === 'field') {
      this.parseField(this.take())
      return
    }
    if (tok.kind === 'word' || tok.kind === 'quoted') {
      this.take()
      this.countTerm(tok.pos)
      checkValue(tok.text, tok.pos)
      if (tok.kind === 'word' && tok.text.includes('*')) {
        throw new QueryError('Wildcards need a field, e.g. cmdline:*mimikatz* or message:*text*.', tok.pos)
      }
      return
    }
    throw new QueryError(`Unexpected '${tok.text}'.`, tok.pos)
  }

  private parseField(tok: Token): void {
    const name = tok.text.toLowerCase()
    const kind = FIELDS[name]
    if (!kind) throw new QueryError(`Unknown field '${tok.text}'. Quote values that contain ':'.`, tok.pos)
    this.countTerm(tok.pos)
    if (tok.rest) {
      checkTerm(name, kind, tok.rest, false, tok.end - tok.rest.length)
      return
    }
    const next = this.peek()
    if (!next) throw new QueryError(`Missing value after '${tok.text}:'.`, tok.end)
    if (next.kind === 'lbrack') {
      this.take()
      this.parseRange(name, kind, next)
      return
    }
    if (next.kind === 'quoted' || next.kind === 'word') {
      this.take()
      checkTerm(name, kind, next.text, next.kind === 'quoted', next.pos)
      return
    }
    throw new QueryError(`Missing value after '${tok.text}:'.`, next.pos)
  }

  private parseRange(name: string, kind: FieldKind, open: Token): void {
    if (kind !== 'int' && kind !== 'ts') throw new QueryError(`Field '${name}' does not support ranges.`, open.pos)
    const bound = (): string | null => {
      const tok = this.peek()
      if (!tok) throw new QueryError('Unterminated range.', open.pos)
      if (tok.kind === 'quoted' || tok.kind === 'word') {
        this.take()
        return tok.kind === 'word' && tok.text === '*' ? null : tok.text
      }
      if (tok.kind === 'field') {
        this.take()
        return `${tok.text}:${tok.rest}`
      }
      throw new QueryError('Expected a range bound.', tok.pos)
    }
    const low = bound()
    const to = this.peek()
    if (!to || to.kind !== 'kw' || to.text !== 'TO') {
      throw new QueryError("Expected 'TO' in range [a TO b].", to ? to.pos : this.query.length)
    }
    this.take()
    const high = bound()
    const close = this.peek()
    if (!close || close.kind !== 'rbrack') throw new QueryError("Missing ']' to close the range.", open.pos)
    this.take()
    if (low === null && high === null) throw new QueryError('A range needs at least one bound.', open.pos)
    for (const b of [low, high]) {
      if (b === null) continue
      if (kind === 'int' && !/^-?[0-9]{1,10}$/.test(b)) throw new QueryError(`'${b.slice(0, 40)}' is not a whole number.`, open.pos)
      if (kind === 'ts' && (Number.isNaN(Date.parse(b)) || !/(Z|[+-]\d{2}:?\d{2})$/i.test(b))) {
        throw new QueryError(`'${b.slice(0, 40)}' is not an ISO-8601 time with a zone.`, open.pos)
      }
    }
  }
}

/** Validate a query. Returns null when it is acceptable, else the error with its position. */
export function validateQuery(query: string): QueryError | null {
  if (query.length > MAX_QUERY) return new QueryError(`Query too long (at most ${MAX_QUERY} characters).`, MAX_QUERY)
  if (!query.trim()) return null
  try {
    new Parser(query).parse()
    return null
  } catch (err) {
    if (err instanceof QueryError) return err
    throw err
  }
}

/** Quote a literal value for the query language (pivots from clicked values). */
export function quoteValue(value: string): string {
  return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`
}

/** Append `field:"value"` (AND) to a query; `negate` adds NOT. */
export function addFilter(query: string, field: string, value: string, negate = false): string {
  const clause = `${negate ? 'NOT ' : ''}${field}:${quoteValue(value)}`
  const base = query.trim()
  if (!base) return clause
  return /\bOR\b/.test(base) ? `(${base}) AND ${clause}` : `${base} AND ${clause}`
}
