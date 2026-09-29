/**
 * Minimal History-API router (no dependency). The URL is the shareable state (guide 17.4):
 * /login, /cases, /cases/:id/:tab?query...
 */
import { useSyncExternalStore } from 'react'

const EVENT = 'dfirbench:navigate'

function subscribe(cb: () => void): () => void {
  window.addEventListener('popstate', cb)
  window.addEventListener(EVENT, cb)
  return () => {
    window.removeEventListener('popstate', cb)
    window.removeEventListener(EVENT, cb)
  }
}

function snapshot(): string {
  return window.location.pathname + window.location.search
}

export function navigate(to: string, opts: { replace?: boolean } = {}): void {
  if (!to.startsWith('/') || to.startsWith('//')) return // same-origin paths only
  if (opts.replace) window.history.replaceState(null, '', to)
  else window.history.pushState(null, '', to)
  window.dispatchEvent(new Event(EVENT))
}

export interface Location {
  path: string
  params: URLSearchParams
}

export function useLocation(): Location {
  const href = useSyncExternalStore(subscribe, snapshot, () => '/')
  const url = new URL(href, 'http://local')
  return { path: url.pathname, params: url.searchParams }
}

export type Route =
  | { name: 'login' }
  | { name: 'cases' }
  | { name: 'case'; id: string; tab: string }
  | { name: 'notfound' }

export function matchRoute(path: string): Route {
  if (path === '/login') return { name: 'login' }
  if (path === '/' || path === '/cases') return { name: 'cases' }
  const m = /^\/cases\/([0-9a-fA-F-]{36})(?:\/([a-z]+))?\/?$/.exec(path)
  if (m) return { name: 'case', id: m[1] as string, tab: m[2] ?? 'overview' }
  return { name: 'notfound' }
}

export function caseHref(id: string, tab: string, params?: Record<string, string>): string {
  const qs = params ? new URLSearchParams(params).toString() : ''
  return `/cases/${encodeURIComponent(id)}/${tab}${qs ? `?${qs}` : ''}`
}
