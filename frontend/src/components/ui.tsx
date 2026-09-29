import type { ButtonHTMLAttributes, ReactNode } from 'react'

import type { Severity } from '@/api/types'
import { errorText } from '@/lib/format'

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost'

const VARIANTS: Record<Variant, string> = {
  primary: 'bg-sky-700 text-white hover:bg-sky-800 disabled:bg-slate-400',
  secondary:
    'border border-slate-300 bg-white text-slate-800 hover:bg-slate-100 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700',
  danger: 'bg-red-700 text-white hover:bg-red-800 disabled:bg-slate-400',
  ghost: 'text-sky-700 hover:underline dark:text-sky-400',
}

export function Button({
  variant = 'secondary',
  className = '',
  type = 'button',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type={type}
      className={`rounded px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 disabled:cursor-not-allowed ${VARIANTS[variant]} ${className}`}
      {...rest}
    />
  )
}

export function ErrorMessage({ error }: { error: unknown }) {
  if (!error) return null
  return (
    <p role="alert" className="text-sm font-medium text-red-700 dark:text-red-400">
      <span aria-hidden="true">&#x2715; </span>
      {errorText(error)}
    </p>
  )
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <p role="status" className="text-sm text-slate-500">
      {label}
    </p>
  )
}

const SEVERITY: Record<Severity, string> = {
  info: 'bg-slate-200 text-slate-800',
  low: 'bg-sky-100 text-sky-900',
  medium: 'bg-amber-100 text-amber-900',
  high: 'bg-orange-200 text-orange-900',
  critical: 'bg-red-200 text-red-900',
}

/** Severity as text + color (color is never the only signal). */
export function SeverityChip({ severity }: { severity: Severity }) {
  return (
    <span className={`rounded px-1.5 py-0.5 text-xs font-semibold uppercase ${SEVERITY[severity] ?? ''}`}>
      {severity}
    </span>
  )
}

export function Panel({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  const id = `panel-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
  return (
    <section
      aria-labelledby={id}
      className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 id={id} className="text-base font-semibold">
          {title}
        </h2>
        {actions}
      </div>
      {children}
    </section>
  )
}

export const inputClass =
  'rounded border border-slate-300 bg-white px-2 py-1 text-sm text-slate-900 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100'
