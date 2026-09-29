import type { AnchorHTMLAttributes, MouseEvent, ReactNode } from 'react'

import { isSameOriginPath, safeHref } from '@/lib/safeHref'

import { navigate } from './router'

type LinkProps = Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'> & {
  to: string
  children: ReactNode
}

/**
 * In-app links navigate through the History API. Anything that is not a same-origin path (for
 * example a URL taken from evidence) must pass the http/https/mailto allow-list, opens in a new
 * tab without referrer/opener, or is rendered as plain text.
 */
export function Link({ to, children, onClick, ...rest }: LinkProps) {
  if (!isSameOriginPath(to)) {
    const href = safeHref(to)
    if (!href) return <span {...rest}>{children}</span>
    return (
      <a {...rest} href={href} target="_blank" rel="noopener noreferrer nofollow">
        {children}
      </a>
    )
  }
  function handle(e: MouseEvent<HTMLAnchorElement>) {
    onClick?.(e)
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
    e.preventDefault()
    navigate(to)
  }
  return (
    <a href={to} onClick={handle} {...rest}>
      {children}
    </a>
  )
}
