/** Hand-written API types (subset of /api/v1/openapi.json). */

export type Permission =
  | 'users:manage'
  | 'case:create'
  | 'case:read'
  | 'case:update'
  | 'case:manage'
  | 'evidence:add'
  | 'evidence:verify'
  | 'evidence:download'
  | 'custody:view'
  | 'investigate'
  | 'alert:update'
  | 'approve'
  | 'audit:view'
  | 'ai:use'
  | 'rules:manage'

export interface TokenResponse {
  access_token: string
  token_type: 'bearer'
  expires_at: string
  refresh_token: string | null
  refresh_expires_at: string
}

export interface LoginResponse {
  mfa_required: boolean
  mfa_challenge: string | null
  mfa_expires_at: string | null
  tokens: TokenResponse | null
}

export interface User {
  id: string
  email: string
  display_name: string
  role: string
  mfa_enabled: boolean
}

export interface Me {
  user: User
  permissions: Permission[]
  auth_method: string
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface Case {
  id: string
  case_number: string
  title: string
  description: string | null
  status: string
  severity: Severity
  classification: string | null
  opened_at: string
  closed_at: string | null
}

export interface CaseDetail extends Case {
  my_case_role: string | null
  my_permissions: Permission[]
}

export interface Page<T> {
  items: T[]
  total: number
}

export interface Evidence {
  id: string
  case_id: string
  label: string
  kind: string
  original_name: string
  size_bytes: number | null
  sha256: string | null
  md5: string | null
  status: string
  source_host: string | null
  acquired_at: string | null
  created_at: string
  /** Set on derived evidence, e.g. a member extracted from a triage bundle. */
  parent_evidence_id?: string | null
}

export interface CustodyEntry {
  seq: number
  ts: string
  actor_label: string
  action: string
  detail: Record<string, unknown>
  prev_hash: string
  entry_hash: string
  key_id: string
}

export interface VerifyResult {
  ok: boolean
  status: 'verified' | 'integrity_failure'
  evidence_status: string
  verified_at: string
  chain: { ok: boolean; entries: number; first_broken_seq: number | null }
}

export interface EventRow {
  id: string
  case_id: string
  evidence_id: string | null
  ts: string
  ts_original: string | null
  source_type: string
  source_file: string | null
  source_record_id: string | null
  host: string | null
  user: string | null
  event_code: string | null
  event_category: string | null
  action: string | null
  outcome: string | null
  process_name: string | null
  pid: number | null
  ppid: number | null
  cmdline: string | null
  file_path: string | null
  file_hash: string | null
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  protocol: string | null
  registry_key: string | null
  message: string | null
  attack_tags: string[]
  tags: string[]
  parser_name: string | null
}

export interface EventDetail extends EventRow {
  raw: Record<string, unknown> | null
}

export interface EventPage {
  items: EventRow[]
  next_cursor: string | null
  limit: number
}

export interface HistogramBucket {
  ts: string
  count: number
  by: Record<string, number>
}

export interface Histogram {
  interval_seconds: number
  from: string | null
  to: string | null
  buckets: HistogramBucket[]
  series: string[]
  total: number
}

export interface FacetValue {
  value: string
  count: number
}

export interface Alert {
  id: string
  case_id: string
  rule_id: string | null
  title: string
  severity: Severity
  confidence: number
  risk_score: number
  status: string
  status_reason: string | null
  host: string | null
  user: string | null
  attack_tags: string[]
  first_seen: string
  last_seen: string
  event_count: number
  stale: boolean
}

export interface AlertHistory {
  id: number
  ts: string
  action: string
  from_status: string | null
  to_status: string | null
  reason: string | null
}

export interface AlertDetail extends Alert {
  details: Record<string, unknown>
  history: AlertHistory[]
}

export interface AlertEvent {
  event_id: string
  event_ts: string
  missing: boolean
  event: EventRow | null
}

export interface AttackRow {
  technique: string
  tactics: string[]
  alerts: number
  max_severity: Severity
}

export interface Note {
  id: string
  case_id: string
  author_id: string
  target_type: string | null
  target_id: string | null
  body_md: string
  tags: string[]
  version: number
  created_at: string
  updated_at: string
  retracted_at: string | null
}

export interface NoteVersion {
  version: number
  action: string
  body_md: string
  user_id: string
  reason: string | null
  created_at: string
}

export interface NoteDetail extends Note {
  versions: NoteVersion[]
}

export interface Bookmark {
  id: string
  user_id: string
  user_name: string | null
  target_type: string
  target_id: string
  comment: string | null
  created_at: string
  event: EventRow | null
}

export interface Entity {
  id: string
  case_id: string
  type: string
  canonical: string
  attributes: Record<string, unknown>
  first_seen: string | null
  last_seen: string | null
  event_count: number
}

export interface EntityDetail extends Entity {
  aliases: { alias_type: string; alias: string }[]
  neighbours: {
    entity: Entity
    relation: string
    direction: 'in' | 'out'
    weight: number
  }[]
  alert_count: number
  pivot_query: string | null
}

export interface GraphEdge {
  src_entity: string
  dst_entity: string
  relation: string
  weight: number
}

export interface Graph {
  nodes: Entity[]
  edges: GraphEdge[]
  truncated: boolean
}

export interface ProcessNode {
  key: string
  pid: number | null
  ppid: number | null
  name: string | null
  kind: string
  ts: string | null
  image: string | null
  cmdline: string | null
  user: string | null
  event_id: string | null
  parent: string | null
  depth: number
  children: number
  flags: string[]
  alerts: number
}

export interface ProcessTree {
  host: string
  nodes: ProcessNode[]
  roots: string[]
  truncated: boolean
  cycles_broken: number
  depth_capped: number
}

export interface Summary {
  events: number
  evidence: number
  entities: number
  notes: number
  jobs_active: number
  first_event: string | null
  last_event: string | null
  alerts_by_status: Record<string, number>
  alerts_by_severity: Record<string, number>
  top_hosts: FacetValue[]
  top_users: FacetValue[]
  risk: { case_risk: number; tactics: string[] }
}

export interface Job {
  id: string
  kind: string
  status: string
  parser: string | null
  progress: number
  error: string | null
  queued_at: string
}
