# PHASE 4: Analysis UI

## Goal
Give analysts a working investigation UI on top of Phases 1-3, and the backend it needs: a strict
KQL-like search language compiled to parameterized SQL, facets, a bounded histogram, context and
capped export; versioned notes and bookmarks; deterministic entity resolution with a capped entity
graph; a per-host process tree; a case summary; and browser-safe token delivery (in-memory access
token + HttpOnly refresh cookie). The React + TypeScript app covers login (with TOTP), cases,
evidence + custody, the timeline Explorer (query bar, time range, histogram, facets, table, event
drawer, context, pivots, export), alerts, the ATT&CK matrix, notes/bookmarks, entities + graph and
the process tree. The web container serves it with a strict CSP.

## In scope / Out of scope
In scope: search language (parser, caps, field allow-list, compiler), `events/search`,
`events/histogram`, `events/facets`, `events/context`, `events/export`, `/search/fields`; notes
(versioned, append-only history, retract), bookmarks; entity extraction + resolution inside the
detection run, entities list/detail, graph; process tree; `/cases/{id}/summary`; refresh cookie +
CSRF header; migration `0007`; the React app (screens above); nginx CSP; tests; live smoke.

Out of scope (see `docs/BACKLOG.md`): generated OpenAPI TypeScript client, Monaco editor and
autocomplete popup, virtualized table (server keyset paging + "load more" instead), ECharts /
Cytoscape (small hand-written SVG charts instead), saved queries API, entity merge suggestions and
approval, time-scoped IP-to-host mapping, domain/file entities, alert nodes in the graph, shortest
path, file browser, WebSocket/SSE job progress (UI polls), suppressions and incident grouping,
asset criticality, per-event ATT&CK tag provenance, Playwright E2E, MFA enrolment UI, admin screens,
export as a background job.

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/search/language.py` | `parse(q) -> Node | None`, `QueryError(message, position)`, AST (`Term`, `FreeText`, `Not`, `And`, `Or`), `FIELDS` allow-list, `quote_value(v)`, caps |
| `backend/app/search/compile.py` | `to_sql(node) -> ColumnElement[bool]` over `Event` (bound parameters only) |
| `backend/app/analysis/entities.py` | pure: `normalize_host/user/ip/hash/process`, `EntityAccumulator.feed(event)`, `.result() -> Resolution` (union-find, deterministic) |
| `backend/app/analysis/proctree.py` | pure: `ProcEvent`, `build_tree(events, max_nodes, max_depth) -> ProcessTree` (guid/pid parents, PID reuse, cycle guard, depth cap, suspicious pairs) |
| `backend/app/services/search.py` | `SearchService.search/histogram/facets/context/export` (case scoped, statement timeout, audit) |
| `backend/app/services/notes.py` | `NoteService.list/get/create/edit/retract`, `BookmarkService.list/create/delete` |
| `backend/app/services/entities.py` | `EntityService.list/get/graph`, `write_resolution(session, case_id, job_id, resolution)` (used by detection) |
| `backend/app/services/proctree.py`, `services/summary.py` | process tree query + builder; case summary |
| `backend/app/services/detection.py` | pass 1 also feeds the `EntityAccumulator`; entities written after alerts (fenced) |
| `backend/app/api/v1/search.py`, `notes.py`, `analysis.py`, `auth.py` | HTTP layer (+ refresh cookie) |
| `backend/alembic/versions/0007_analysis.py` | schema + grants below |
| `frontend/src/**` | app (see Frontend) |
| `infra/docker/nginx.conf` | strict CSP and security headers on every location |
| `scripts/phase4-smoke.py`, `scripts/verify-phase4.sh` | live smoke, verification |

## Search language
```
query  := or
or     := and ("OR" and)*
and    := unary (["AND"] unary)*          # adjacency = AND
unary  := "NOT" unary | "(" or ")" | field ":" value | field ":" "[" bound "TO" bound "]" | text
value  := quoted | word                    # "*" wildcards in words; field:* = field exists
bound  := quoted | word | "*"              # "*" = open end
```
Keywords are upper case; lower-case `and`/`or` are text. Quoted strings escape only `\"` and `\\`.
Fields (allow-list, `GET /search/fields`): text `host user event_code event_category action outcome
source_type source_file source_record_id process_name cmdline file_path file_hash protocol
registry_key message parser_name`; int `pid ppid src_port dst_port`; ip `src_ip dst_ip ip` (ip =
either; CIDR allowed); ts `ts` (range only, ISO-8601 with zone); array `attack_tags tags`; uuid
`evidence_id job_id`. Text equality is case-insensitive (`lower(col) = lower(:v)`), wildcards
compile to `ILIKE ... ESCAPE '\'` with `%`/`_` escaped. Free text uses the `ix_events_fts`
expression (`plainto_tsquery`, phrases `phraseto_tsquery`). `NOT` is null-safe
(`NOT coalesce(x, false)`).
Caps: query 2000 chars, depth 12, 40 terms, value 512 chars, 4 wildcards per value, a leading
wildcard needs >= 3 literal characters, no wildcard in free text or non-text fields. Errors: 422
`invalid_query` with `position`. Every search/facet/histogram runs with `SET LOCAL
statement_timeout` (`SEARCH_TIMEOUT_MS`, default 15000; timeout -> 422 `query_timeout`).

## Entity resolution (deterministic)
Run inside every detection job (pass 1 stream; setting `ENTITY_RESOLUTION`, default on).
* host: lowercase, trailing dot removed; canonical = first label (short name), aliases `hostname`
  (as seen, lowercased) and `fqdn`; an IP-looking host becomes an ip entity.
* user: `DOMAIN\name` -> `domain\name`; `name@corp.local` -> `corp\name` (first domain label);
  bare `name`; SIDs are aliases; placeholders (`-`, `NULL SID`, `S-1-0-0`, empty) skipped.
  Strong merge (union-find) only when one event states SID and name together (EVTX
  Subject*/Target* fields). Group canonical = smallest `domain\name`, else smallest name, else SID.
* ip: `ipaddress` canonical text; attribute `scope` (private/public/loopback/...).
* process: `host/image-basename` lowercase (per host executable); hash: lowercase hex of 32/40/64
  chars (`algo` attribute), others ignored.
* relations: `logged_on`, `failed_logon`, `seen_on` (user -> host), `connected_to` (src ip -> host,
  host -> dst ip), `executed` (user -> process), `ran_on` (process -> host), `has_hash`.
* Caps: 50 000 entities, 200 000 links, 20 aliases per entity; hitting a cap sets
  `entities.capped` in the run manifest (detection outcome unchanged).
* Writes: upsert on `(case_id, type, canonical)` and `(case_id, src, dst, relation)`;
  aliases `ON CONFLICT DO NOTHING`; sorted keys (stable lock order); fenced by the job token.

## Process tree
`GET /cases/{id}/process-tree?host=` builds from process-create events (Sysmon 1, 4688) and other
events with a pid on that host (observed processes, one per pid+name). Parent = ParentProcessGuid
match, else the latest earlier node with pid == ppid (PID reuse), else a synthetic parent node for
the ppid. Cycles are refused (walk-up check), depth capped (`max_depth` <= 128, default 64), nodes
capped (`limit` <= 5000). Flags: suspicious parent/child pairs (Office/mshta/wmiprvse ->
shells/LOLBins), alert count per node.

## Data model changes (`0007_analysis.py`)
* notes: `version`, `updated_at`, `updated_by`, `retracted_at`, `retracted_by`, CHECK
  target_type, index `(case_id, created_at)`. `note_versions` (append-only: trigger + S/I grants):
  `(note_id, version)` unique, body, tags, action created|edited|retracted, user, time, reason.
* bookmarks: UNIQUE `(case_id, user_id, target_type, target_id)`, CHECK target_type.
* entities: `event_count`, `updated_at`, `last_job_id`, CHECK type, index `(case_id, type)`.
* entity_links: `first_seen`, `last_seen`, UNIQUE `(case_id, src_entity, dst_entity, relation)`,
  CHECK relation, index `(case_id, dst_entity)`.
* Grants for `dfirbench_app`: notes S/I + UPDATE(body_md, tags, version, updated_at, updated_by,
  retracted_at, retracted_by) only; note_versions S/I; bookmarks S/I/D; entities S/I/U;
  entity_aliases S/I; entity_links S/I/U. No new SECURITY DEFINER functions.

## API changes (all under `/api/v1`)
| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/search/fields` | authenticated | allow-list with types and ops |
| POST | `/cases/{id}/events/search` | `case:read` | `{query, from, to, order, limit<=500, cursor}`; audited |
| POST | `/cases/{id}/events/histogram` | `case:read` | `{query, from, to, buckets 10-200}`; interval from a fixed ladder; stacked by source_type (<= 12 series + other) |
| POST | `/cases/{id}/events/facets` | `case:read` | `{query, from, to, fields<=8, size<=50}` |
| POST | `/cases/{id}/events/context` | `case:read` | `{event_id, minutes<=1440, limit<=500}` same host |
| POST | `/cases/{id}/events/export` | `investigate` | `{query, from, to, format csv|json, limit<=10000}`; CSV formula-neutralised; audited with sha256 |
| GET/POST | `/cases/{id}/notes` | `case:read` / `investigate` | target validated in the case |
| GET/PATCH | `/notes/{id}` | `case:read` / author | PATCH needs `expected_version` (409 stale) |
| POST | `/notes/{id}/retract` | author or `case:manage` | keeps history |
| GET/POST | `/cases/{id}/bookmarks` | `investigate` | POST idempotent (200 existing / 201 new) |
| DELETE | `/cases/{id}/bookmarks/{bid}` | owner or `case:manage` | audited |
| GET | `/cases/{id}/entities`, `/entities/{id}` | `case:read` | detail: aliases, neighbours, alerts, pivot query |
| GET | `/cases/{id}/graph` | `case:read` | `entity_id?`, `depth<=2`, `types`, `relations`, `max_nodes<=500`, `max_edges<=2000` |
| GET | `/cases/{id}/process-tree` | `case:read` | `host` required |
| GET | `/cases/{id}/summary` | `case:read` | counts, alerts by status/severity, risk, top hosts/users |
| POST | `/auth/login`, `/auth/mfa/verify`, `/auth/refresh`, `/auth/logout` | - | header `X-Token-Delivery: cookie`: refresh token only in `dfir_refresh` (HttpOnly, Secure, SameSite=Strict, Path=/api/v1/auth), omitted from JSON; refresh/logout read the cookie only with that header (CSRF) |
Writes follow the Phase 1-3 pattern: `FOR SHARE` on the case + open re-check (closed -> 409),
row lock + re-check for read-modify-write, audit rows. Cross-case ids answer 404.

## Frontend
Own History-API router (`/login`, `/cases`, `/cases/:id/:tab`; Explorer state in the URL = shareable
links), TanStack Query, no new npm dependencies. Access token in memory only; refresh via cookie;
401 -> one single-flight refresh -> retry once -> logout. Evidence/event/alert strings rendered as
React text only (lint bans `dangerouslySetInnerHTML`); links built from data pass `safeHref`
(http/https/mailto allow-list). Actions hidden by `my_permissions` (the server enforces them).
Tables: focusable rows, arrow keys, Enter opens the drawer; dialogs trap focus and close on Escape.

## Test plan
* Unit (no Docker): search parser (grammar, caps, errors, hostile input, property test that the
  parser never raises anything but `QueryError`), compiler (SQL text has bound parameters only),
  entity normalization/resolution determinism (order independence), process tree (guid, PID reuse,
  cycles, depth cap, suspicious pairs), cookie options.
* Integration (compose Postgres): search/histogram/facets/context/export end to end incl. RBAC,
  404 cross-case, SQL-injection strings, timeouts; notes versioning + concurrent edits (one wins)
  + retract + closed case; bookmarks idempotency/ownership; entities from a detection run (EVTX SID
  merge, host FQDN merge), graph caps, process tree from synthetic Sysmon events incl. a guid
  cycle; summary; refresh-cookie flow + CSRF header; grants (app role denials) and migration round
  trip.
* Frontend (vitest + Testing Library): search bar parse errors, hostile strings rendered as text,
  auth refresh-once flow, RBAC-hidden actions, safeHref.
* Live: `scripts/phase4-smoke.py` (search, facets, histogram, notes, bookmarks, entities, graph,
  process tree, summary, export, cookie refresh, web CSP header).

## Acceptance criteria (executable)
1. Search language: `pytest tests/unit/test_search_language.py`; `tests/integration/test_analysis.py -k search`.
2. Facets + histogram bounded: `-k "facets or histogram"`.
3. Notes/bookmarks: `-k "note or bookmark"`.
4. Entity resolution + graph: `tests/unit/test_entities.py`, `-k "entit or graph"`.
5. Process tree: `tests/unit/test_proctree.py`, `-k process_tree`.
6. Auth cookie: `tests/integration/test_analysis.py -k cookie`.
7. Frontend: `npm run lint && npm run typecheck && npm test && npm run build`.
8. Live: `scripts/phase4-smoke.py` prints `PHASE 4 SMOKE PASSED`; the web app answers with the CSP.

## Verification command
```bash
bash scripts/verify-phase4.sh
```

## Implementation notes / deliberate deviations
* Parser is hand-written recursive descent instead of `lark` (no new dependency; strict caps are
  easier to enforce and test).
* Entity resolution runs inside the detection job (one scan, job fencing and manifest reused)
  instead of a separate job kind.
* Export is synchronous and capped (10 000 rows) instead of a job; audited with the output hash.
* Charts and the graph are small SVG components, the query bar a plain input with client-side
  validation mirroring the server grammar; the server stays authoritative.
