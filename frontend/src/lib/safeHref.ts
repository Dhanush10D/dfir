/**
 * Links built from evidence/event data must never become `javascript:`, `data:` or other active
 * URLs. Only http(s) and mailto survive; everything else returns null (render as plain text).
 */
const ALLOWED = new Set(['http:', 'https:', 'mailto:'])

/** Control characters and whitespace inside a URL are a classic scheme-filter bypass. */
function hasControlOrSpace(text: string): boolean {
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0
    if (code <= 0x20 || code === 0x7f || /\s/.test(ch)) return true
  }
  return false
}

export function safeHref(value: string | null | undefined): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!trimmed || hasControlOrSpace(trimmed)) return null
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return null
  }
  return ALLOWED.has(url.protocol) ? url.href : null
}
