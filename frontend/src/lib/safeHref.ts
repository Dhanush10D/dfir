/**
 * Links built from evidence/event data must never become `javascript:`, `data:` or other active
 * URLs. Only http(s) and mailto survive; everything else returns null (render as plain text).
 *
 * Browsers strip leading/trailing C0 controls and spaces and remove tab/CR/LF anywhere before they
 * read the scheme, and they treat `\` like `/` in special URLs. So: trim those characters at the
 * ends, refuse any that remain inside, check the scheme case-insensitively against the allow-list
 * *before* parsing, then check the parsed protocol again.
 */
const ALLOWED = new Set(['http:', 'https:', 'mailto:'])
const SCHEME = /^([a-zA-Z][a-zA-Z0-9+.-]*):/

function isControlOrSpace(code: number): boolean {
  // C0 controls + space, DEL, C1 controls, and Unicode spaces / line separators / BOM.
  return (
    code <= 0x20 ||
    (code >= 0x7f && code <= 0x9f) ||
    code === 0xa0 ||
    code === 0x1680 ||
    (code >= 0x2000 && code <= 0x200f) ||
    (code >= 0x2028 && code <= 0x202f) ||
    code === 0x205f ||
    code === 0x3000 ||
    code === 0xfeff
  )
}

/** Remove whitespace and control characters from both ends. */
export function trimControl(value: string): string {
  let start = 0
  let end = value.length
  while (start < end && isControlOrSpace(value.charCodeAt(start))) start++
  while (end > start && isControlOrSpace(value.charCodeAt(end - 1))) end--
  return value.slice(start, end)
}

function hasControlOrSpace(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    if (isControlOrSpace(text.charCodeAt(i))) return true
  }
  return false
}

/**
 * True for a same-origin absolute path such as `/cases/x`. Rejects protocol-relative forms
 * (`//host`, `/\host`, `\\host`) and anything with control characters or whitespace.
 */
export function isSameOriginPath(value: string): boolean {
  if (!value.startsWith('/') || hasControlOrSpace(value)) return false
  const second = value.charAt(1)
  return second !== '/' && second !== '\\'
}

export function safeHref(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null
  const trimmed = trimControl(value)
  if (!trimmed || hasControlOrSpace(trimmed)) return null
  const scheme = SCHEME.exec(trimmed)
  if (!scheme || !ALLOWED.has(`${(scheme[1] as string).toLowerCase()}:`)) return null
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return null
  }
  if (!ALLOWED.has(url.protocol)) return null
  if (url.protocol !== 'mailto:' && !url.hostname) return null
  return url.href
}
