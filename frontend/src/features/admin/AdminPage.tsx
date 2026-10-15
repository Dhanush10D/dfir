import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'

import { ApiError } from '@/api/client'
import { api } from '@/api/endpoints'
import type { AdminUser, UserRole } from '@/api/types'
import { useAuth } from '@/auth/AuthContext'
import { Button, ErrorMessage, inputClass, Loading, Panel } from '@/components/ui'
import { HealthStatus } from '@/features/health/HealthStatus'
import { formatUtc } from '@/lib/format'

/**
 * Administration (users:manage): accounts, roles, case access, AI provider and recent audit
 * activity. The server enforces every rule; granting lead/admin, (de)activating an account and
 * resetting MFA need the acting admin's password again. Passwords are never shown or stored here.
 */

const ROLES: { id: UserRole; label: string; help: string }[] = [
  { id: 'analyst', label: 'Analyst', help: 'Investigates: evidence, timeline, alerts, AI, playbooks. Cannot approve.' },
  { id: 'lead', label: 'Lead', help: 'Runs cases: everything an analyst does, plus approvals, reports and rules.' },
  { id: 'viewer', label: 'Viewer', help: 'Read-only access to the cases they are added to.' },
  { id: 'auditor', label: 'Auditor', help: 'Read-only on every case, plus custody and the audit log.' },
  { id: 'admin', label: 'Admin', help: 'Everything, including accounts and integrations. Sees every case.' },
]
const PRIVILEGED = new Set<UserRole>(['admin', 'lead'])
const CASE_ROLES: UserRole[] = ['analyst', 'lead', 'viewer']

const labelClass = 'flex flex-col gap-1 text-sm'
const fieldClass = `${inputClass} w-full`
const subPanelClass = 'rounded-md border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950/40'

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div className="flex flex-col gap-1">
      <label className={labelClass}>
        <span className="font-medium">{label}</span>
        {children}
      </label>
      {hint && <span className="text-xs text-slate-500">{hint}</span>}
    </div>
  )
}

function Stat({ label, value, note }: { label: string; value: ReactNode; note?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="text-2xl font-semibold">{value}</div>
      <div className="text-sm text-slate-600 dark:text-slate-400">{label}</div>
      {note && <div className="mt-1 text-xs text-slate-500">{note}</div>}
    </div>
  )
}

/** The server's password-policy problems, when it sent them. */
function Problems({ error }: { error: unknown }) {
  if (!(error instanceof ApiError)) return null
  const problems = error.details.problems
  if (!Array.isArray(problems) || problems.length === 0) return null
  return (
    <ul className="list-inside list-disc text-sm text-red-700 dark:text-red-400">
      {problems.map((p) => (
        <li key={String(p)}>Password {String(p)}</li>
      ))}
    </ul>
  )
}

function generatePassword(): string {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_!@#%'
  const bytes = crypto.getRandomValues(new Uint8Array(18))
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('')
}

function isLocked(u: AdminUser) {
  return u.locked_until !== null && new Date(u.locked_until).getTime() > Date.now()
}

function StatusBadge({ user }: { user: AdminUser }) {
  const [text, cls] = !user.is_active
    ? ['disabled', 'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200']
    : isLocked(user)
      ? ['locked', 'bg-red-100 text-red-900 dark:bg-red-900/40 dark:text-red-200']
      : ['active', 'bg-emerald-100 text-emerald-900 dark:bg-emerald-900/40 dark:text-emerald-200']
  return <span className={`rounded px-2 py-0.5 text-xs font-medium ${cls}`}>{text}</span>
}

function CreateUserForm() {
  const client = useQueryClient()
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState<UserRole>('analyst')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [adminPassword, setAdminPassword] = useState('')
  const [created, setCreated] = useState<AdminUser | null>(null)
  const privileged = PRIVILEGED.has(role)
  const mismatch = confirm !== '' && confirm !== password
  const create = useMutation({
    mutationFn: () =>
      api.createUser({
        email: email.trim(),
        display_name: name.trim(),
        role,
        password,
        ...(privileged ? { admin_password: adminPassword } : {}),
      }),
    onSuccess: (user) => {
      setCreated(user)
      setName('')
      setEmail('')
      setPassword('') // never keep a password in the page after it was sent
      setConfirm('')
      setAdminPassword('')
      setShow(false)
      void client.invalidateQueries({ queryKey: ['admin-users'] })
    },
  })
  function submit(e: FormEvent) {
    e.preventDefault()
    if (password !== confirm) return
    setCreated(null)
    create.mutate()
  }
  function generate() {
    const p = generatePassword()
    setPassword(p)
    setConfirm(p)
    setShow(true)
  }
  return (
    <form onSubmit={submit} aria-label="Create account" className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Full name">
          <input className={fieldClass} required maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="E-mail (used to sign in)">
          <input
            className={fieldClass}
            type="email"
            required
            maxLength={320}
            autoComplete="off"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </Field>
        <Field label="Role" hint={ROLES.find((r) => r.id === role)?.help}>
          <select className={fieldClass} value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
            {ROLES.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Password" hint="At least 12 characters, not a common password, not the e-mail name.">
          <input
            className={`${fieldClass} font-mono`}
            type={show ? 'text' : 'password'}
            required
            autoComplete="new-password"
            maxLength={256}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </Field>
        <Field label="Confirm password">
          <input
            className={`${fieldClass} font-mono`}
            type={show ? 'text' : 'password'}
            required
            autoComplete="new-password"
            maxLength={256}
            value={confirm}
            aria-invalid={mismatch}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </Field>
        <div className="flex items-end gap-3 pb-1">
          <Button onClick={generate}>Generate strong password</Button>
          <label className="inline-flex items-center gap-2 text-sm">
            <input type="checkbox" checked={show} onChange={(e) => setShow(e.target.checked)} />
            Show
          </label>
        </div>
        {privileged && (
          <Field label="Your password (to confirm granting this role)">
            <input
              className={fieldClass}
              type="password"
              required
              autoComplete="current-password"
              value={adminPassword}
              onChange={(e) => setAdminPassword(e.target.value)}
            />
          </Field>
        )}
      </div>
      {mismatch && <p className="text-sm text-red-700 dark:text-red-400">The passwords do not match.</p>}
      <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 pt-4 dark:border-slate-800">
        <Button type="submit" variant="primary" disabled={create.isPending || mismatch}>
          Create account
        </Button>
      </div>
      {created && (
        <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">
          Account created for {created.display_name} ({created.email}) as {created.role}.
          {created.role !== 'admin' && created.role !== 'auditor' && ' Add them to a case below so they can see it.'}
        </p>
      )}
      <ErrorMessage error={create.error} />
      <Problems error={create.error} />
    </form>
  )
}

function ManageUser({ user, self, onDone }: { user: AdminUser; self: boolean; onDone: () => void }) {
  const client = useQueryClient()
  const [name, setName] = useState(user.display_name)
  const [role, setRole] = useState<UserRole>(user.role)
  const [adminPassword, setAdminPassword] = useState('')
  const update = useMutation({
    mutationFn: (body: Parameters<typeof api.updateUser>[1]) => api.updateUser(user.id, body),
    onSuccess: () => {
      setAdminPassword('')
      void client.invalidateQueries({ queryKey: ['admin-users'] })
      onDone()
    },
  })
  const withPw = adminPassword ? { admin_password: adminPassword } : {}
  const save = () => {
    const body: Parameters<typeof api.updateUser>[1] = {}
    if (name.trim() !== user.display_name) body.display_name = name.trim()
    if (role !== user.role) Object.assign(body, { role }, withPw)
    update.mutate(body)
  }
  const changed = name.trim() !== user.display_name || role !== user.role
  return (
    <div className={`${subPanelClass} space-y-3`}>
      <div className="grid gap-4 sm:grid-cols-3">
        <Field label="Full name">
          <input className={fieldClass} maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Role">
          <select className={fieldClass} value={role} disabled={self} onChange={(e) => setRole(e.target.value as UserRole)}>
            {ROLES.map((r) => (
              <option key={r.id} value={r.id}>
                {r.label}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Your password" hint="Needed for role, enable/disable and MFA changes.">
          <input
            className={fieldClass}
            type="password"
            autoComplete="current-password"
            value={adminPassword}
            onChange={(e) => setAdminPassword(e.target.value)}
          />
        </Field>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" disabled={!changed || update.isPending} onClick={save}>
          Save changes
        </Button>
        {!self && (
          <Button
            variant={user.is_active ? 'danger' : 'secondary'}
            disabled={update.isPending || !adminPassword}
            onClick={() => update.mutate({ is_active: !user.is_active, ...withPw })}
          >
            {user.is_active ? 'Disable account' : 'Enable account'}
          </Button>
        )}
        {isLocked(user) && (
          <Button disabled={update.isPending} onClick={() => update.mutate({ unlock: true, ...withPw })}>
            Unlock
          </Button>
        )}
        {user.mfa_enabled && !self && (
          <Button disabled={update.isPending || !adminPassword} onClick={() => update.mutate({ reset_mfa: true, ...withPw })}>
            Reset MFA
          </Button>
        )}
        <Button variant="ghost" onClick={onDone}>
          Close
        </Button>
      </div>
      {self && <p className="text-xs text-slate-500">You cannot change your own role or disable yourself.</p>}
      <ErrorMessage error={update.error} />
    </div>
  )
}

function UsersTable({ users }: { users: AdminUser[] }) {
  const { me } = useAuth()
  const [open, setOpen] = useState<string | null>(null)
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Accounts</caption>
        <thead className="text-xs text-slate-500 uppercase">
          <tr>
            <th scope="col" className="py-2 pr-3">Name</th>
            <th scope="col" className="pr-3">E-mail</th>
            <th scope="col" className="pr-3">Role</th>
            <th scope="col" className="pr-3">Status</th>
            <th scope="col" className="pr-3">MFA</th>
            <th scope="col" className="pr-3">Last sign-in (UTC)</th>
            <th scope="col" className="pr-3">Created (UTC)</th>
            <th scope="col">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <UserRow key={u.id} user={u} self={u.id === me?.user.id} open={open === u.id} setOpen={setOpen} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

function UserRow({
  user: u,
  self,
  open,
  setOpen,
}: {
  user: AdminUser
  self: boolean
  open: boolean
  setOpen: (id: string | null) => void
}) {
  return (
    <>
      <tr className="border-t border-slate-200 dark:border-slate-800">
        <td className="py-2 pr-3 font-medium">
          {u.display_name}
          {self && <span className="ml-2 text-xs text-slate-500">(you)</span>}
        </td>
        <td className="pr-3">{u.email}</td>
        <td className="pr-3 capitalize">{u.role}</td>
        <td className="pr-3">
          <StatusBadge user={u} />
        </td>
        <td className="pr-3">{u.mfa_enabled ? 'on' : 'off'}</td>
        <td className="pr-3 text-xs whitespace-nowrap">{u.last_login_at ? formatUtc(u.last_login_at) : 'never'}</td>
        <td className="pr-3 text-xs whitespace-nowrap">{formatUtc(u.created_at)}</td>
        <td className="text-right">
          <Button variant="ghost" aria-expanded={open} onClick={() => setOpen(open ? null : u.id)}>
            Manage
          </Button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={8} className="pb-3">
            <ManageUser user={u} self={self} onDone={() => setOpen(null)} />
          </td>
        </tr>
      )}
    </>
  )
}

function CaseAccess({ users }: { users: AdminUser[] }) {
  const client = useQueryClient()
  const cases = useQuery({ queryKey: ['cases'], queryFn: ({ signal }) => api.cases(signal) })
  const [caseId, setCaseId] = useState('')
  const [userId, setUserId] = useState('')
  const [role, setRole] = useState<UserRole>('analyst')
  const chosen = caseId || cases.data?.items[0]?.id || ''
  const members = useQuery({
    queryKey: ['members', chosen],
    queryFn: ({ signal }) => api.members(chosen, signal),
    enabled: chosen !== '',
  })
  const refresh = () => void client.invalidateQueries({ queryKey: ['members', chosen] })
  const add = useMutation({
    mutationFn: () => api.setMember(chosen, userId, role),
    onSuccess: () => {
      setUserId('')
      refresh()
    },
  })
  const remove = useMutation({ mutationFn: (id: string) => api.removeMember(chosen, id), onSuccess: refresh })
  // Admins and auditors already see every case; offer only accounts that need membership.
  const memberIds = new Set((members.data ?? []).map((m) => m.user_id))
  const candidates = users.filter((u) => u.is_active && u.role !== 'admin' && u.role !== 'auditor' && !memberIds.has(u.id))
  function submit(e: FormEvent) {
    e.preventDefault()
    if (userId) add.mutate()
  }
  if (cases.isPending) return <Loading />
  if (cases.error) return <ErrorMessage error={cases.error} />
  if (!cases.data.items.length) return <p className="text-sm text-slate-500">No cases yet.</p>
  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-400">
        Admins and auditors see every case. Everyone else only sees the cases they are added to here. A lead on a
        case can approve that case&apos;s playbook actions.
      </p>
      <div className="max-w-xl">
        <Field label="Case">
          <select className={fieldClass} value={chosen} onChange={(e) => setCaseId(e.target.value)}>
            {cases.data.items.map((c) => (
              <option key={c.id} value={c.id}>
                {c.case_number}: {c.title}
              </option>
            ))}
          </select>
        </Field>
      </div>
      {members.isPending && <Loading />}
      <ErrorMessage error={members.error} />
      {members.data && (
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Case members</caption>
          <thead className="text-xs text-slate-500 uppercase">
            <tr>
              <th scope="col" className="py-2 pr-3">Member</th>
              <th scope="col" className="pr-3">E-mail</th>
              <th scope="col" className="pr-3">Account role</th>
              <th scope="col" className="pr-3">Role on this case</th>
              <th scope="col">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {members.data.map((m) => (
              <tr key={m.user_id} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-2 pr-3 font-medium">{m.display_name}</td>
                <td className="pr-3">{m.email}</td>
                <td className="pr-3 capitalize">{m.global_role}</td>
                <td className="pr-3 capitalize">{m.case_role}</td>
                <td className="text-right">
                  <Button variant="ghost" disabled={remove.isPending} onClick={() => remove.mutate(m.user_id)}>
                    Remove
                  </Button>
                </td>
              </tr>
            ))}
            {members.data.length === 0 && (
              <tr>
                <td colSpan={5} className="py-2 text-slate-500">
                  Nobody has been added to this case yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
      <form onSubmit={submit} aria-label="Add case member" className={`${subPanelClass} space-y-4`}>
        <h3 className="text-sm font-semibold">Add someone to this case</h3>
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Person">
            <select className={fieldClass} value={userId} onChange={(e) => setUserId(e.target.value)}>
              <option value="">Choose an account…</option>
              {candidates.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.display_name} ({u.role})
                </option>
              ))}
            </select>
          </Field>
          <Field label="Role on this case" hint="They get the lower of this and their account role.">
            <select className={fieldClass} value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
              {CASE_ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </Field>
          <div className="flex items-end pb-0.5">
            <Button type="submit" variant="primary" disabled={!userId || add.isPending}>
              Add to case
            </Button>
          </div>
        </div>
        <ErrorMessage error={add.error ?? remove.error} />
      </form>
    </div>
  )
}

function RecentActivity({ users }: { users: AdminUser[] }) {
  const q = useQuery({ queryKey: ['admin-audit'], queryFn: ({ signal }) => api.audit(25, signal) })
  const who = new Map(users.map((u) => [u.id, u.display_name]))
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  return (
    <div className="overflow-x-auto">
      <p className="mb-2 text-xs text-slate-500">
        Latest {q.data.items.length} of {q.data.total} audit entries (append-only).
      </p>
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Recent audit entries</caption>
        <thead className="text-xs text-slate-500 uppercase">
          <tr>
            <th scope="col" className="py-2 pr-3">Time (UTC)</th>
            <th scope="col" className="pr-3">Who</th>
            <th scope="col" className="pr-3">Action</th>
            <th scope="col" className="pr-3">Object</th>
            <th scope="col">Result</th>
          </tr>
        </thead>
        <tbody>
          {q.data.items.map((a) => (
            <tr key={a.id} className="border-t border-slate-200 dark:border-slate-800">
              <td className="py-1.5 pr-3 text-xs whitespace-nowrap">{formatUtc(a.ts)}</td>
              <td className="pr-3">{a.user_id ? (who.get(a.user_id) ?? 'removed account') : 'system'}</td>
              <td className="pr-3 font-mono text-xs">{a.action}</td>
              <td className="pr-3 text-xs text-slate-500">{a.object_type ?? '–'}</td>
              <td className="text-xs">{a.status ?? '–'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AiProvider() {
  const q = useQuery({ queryKey: ['ai-status'], queryFn: ({ signal }) => api.aiStatus(signal) })
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorMessage error={q.error} />
  const s = q.data
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
      <dt className="text-slate-500">AI</dt>
      <dd className="font-medium">{s.enabled ? (s.configured ? 'on' : 'on, provider not configured') : 'off'}</dd>
      <dt className="text-slate-500">Provider</dt>
      <dd>
        {s.provider}
        {s.local_only ? ' (local only)' : ''}
      </dd>
      {Object.entries(s.models).map(([k, v]) => (
        <Pair key={k} label={`${k[0]!.toUpperCase()}${k.slice(1)} model`} value={v} />
      ))}
      <dt className="text-slate-500">Redaction</dt>
      <dd>{s.redaction_policy}</dd>
    </dl>
  )
}

function Pair({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="text-slate-500">{label}</dt>
      <dd className="font-mono text-xs leading-5 break-all">{value}</dd>
    </>
  )
}

export function AdminPage() {
  const { can } = useAuth()
  const allowed = can('users:manage')
  const users = useQuery({ queryKey: ['admin-users'], queryFn: ({ signal }) => api.users(signal), enabled: allowed })
  const cases = useQuery({ queryKey: ['cases'], queryFn: ({ signal }) => api.cases(signal), enabled: allowed })
  if (!allowed) return <p>The admin page is for administrators.</p>
  const list = users.data ?? []
  const active = list.filter((u) => u.is_active)
  const byRole = ROLES.map((r) => `${active.filter((u) => u.role === r.id).length} ${r.id}`).join(' · ')
  const openCases = (cases.data?.items ?? []).filter((c) => c.status !== 'closed').length
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Administration</h1>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="Active accounts" value={users.data ? active.length : '…'} note={users.data ? byRole : undefined} />
        <Stat label="Disabled or locked" value={users.data ? list.filter((u) => !u.is_active || isLocked(u)).length : '…'} />
        <Stat label="Accounts with MFA" value={users.data ? `${active.filter((u) => u.mfa_enabled).length} / ${active.length}` : '…'} />
        <Stat label="Open cases" value={cases.data ? openCases : '…'} note={cases.data ? `${cases.data.items.length} in total` : undefined} />
      </div>
      <Panel title="Create an account">
        <CreateUserForm />
      </Panel>
      <Panel title="Accounts">
        {users.isPending && <Loading />}
        <ErrorMessage error={users.error} />
        {users.data && <UsersTable users={users.data} />}
      </Panel>
      <Panel title="Case access">
        <CaseAccess users={list} />
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="System">
          <HealthStatus />
        </Panel>
        <Panel title="AI provider">
          <AiProvider />
        </Panel>
      </div>
      <Panel title="Recent activity">
        <RecentActivity users={list} />
      </Panel>
    </div>
  )
}
