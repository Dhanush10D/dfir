# PHASE 7: AI layer

## Goal
Add assistive, grounded and verifiable AI to the workbench (guide 13, 22.4): one LLM gateway with
pluggable providers (Anthropic by default, Ollama, OpenAI-compatible, and an offline fake), evidence
packs that give the model numbered, sanitized, delimited records, schema and citation validators
that run server-side before any output can be accepted, prompt-injection defenses and an injection
suite, and five features: natural-language search (A1), alert explanation (A2), attack narrative
(A3), case chat over a pgvector index (A5) and static script/command explanation (A7). Every call
is recorded with its provenance (provider, model, prompt version, input/prompt/output hashes, times,
tokens) in `ai_interactions`. AI output never changes evidence, custody, alerts or verdicts; a
human accepts or rejects it (RBAC, row lock, audit record). An evaluation harness with packaged
datasets runs offline in CI.

## In scope / Out of scope
In scope:
* `app/ai/` package: gateway + providers, evidence packs, sanitizer + injection heuristics,
  redaction, versioned prompts, output schemas, validators, feature runner, deterministic script
  decoder, hashed local embeddings, chunking/retrieval helpers, fake/fixture providers, eval
  harness (`python -m app.ai.eval`) with datasets.
* `services/ai.py` (features, provenance, review, feedback, per-case AI switch) and
  `services/ai_index.py` (RAG index build/freshness/retrieval); migration 0009; API under `/ai`;
  search field `id` (so citations open the event in the Explorer).
* Frontend: an "AI analyst" case tab (NL search, chat, narrative, script explain, history with
  accept/reject/feedback and a transparency view) and an "Explain with AI" panel on alerts.
* Tests (unit, integration, injection suite, eval targets), `docs/ai.md`, live smoke, verify script.

Out of scope (see `docs/BACKLOG.md`): A4 report drafting and A14 report QA (Phase 8 reporting),
A6 IOC extraction, A8 standalone ATT&CK suggestions (A2/A7 already return candidates), A9
anomaly/beaconing analytics with scikit-learn (P2 in the guide; not in the Phase 7 roadmap row),
A10 similar cases, A11 playbook recommendation (Phase 9), A12 log-format helper, A13 next-step
suggestions, sentence-transformer embeddings in a `worker-ai` image, background (Celery) indexing
and narrative jobs, one-click IOC creation from A7 indicators, reversible redaction of free text by
NER, per-user cost dashboards.

## Standard-profile decisions (made without the owner; recorded here)
1. **Only `app/ai/gateway.py` talks to a model.** It holds the provider classes that do network
   I/O: `AnthropicProvider` (official `anthropic` SDK 1.9.0, pinned), `OpenAICompatProvider`
   (`/v1/chat/completions` with a JSON-schema `response_format`, `httpx2`) and `OllamaProvider`
   (`/api/chat` with `format=<schema>`, `/api/embed`). `FakeProvider` and `FixtureProvider`
   (`app/ai/fake.py`) never touch the network. A unit test fails if `anthropic`, `httpx2`,
   `urllib.request`, `requests` or `socket` is imported anywhere else under `app/ai/` or in the
   AI service/router.
2. **Provider and models are configuration.** Defaults: `LLM_PROVIDER=anthropic`,
   `LLM_MODEL_FAST=claude-haiku-4-5-20251001` (A1 translation), `LLM_MODEL_STRONG=claude-sonnet-5-5`
   (A2/A3/A5/A7). The API key is `LLM_API_KEY` (a SecretStr, never logged) and is passed to the SDK
   explicitly, so ambient `ANTHROPIC_*` variables and CLI profiles are never used. AI is off
   unless `ENABLE_AI=true`; enabled without a key -> 503 `ai_unavailable`. `LLM_PROVIDER=fake` is
   refused when `APP_ENV=prod`. The Anthropic call uses structured outputs
   (`output_config.format` json_schema; constraints the API does not support, such as
   `maxLength`, are stripped from the provider copy and enforced by our own validation), no
   `temperature` (not accepted by current models), optional `LLM_EFFORT`, and the server-side
   refusal fallback (`fallbacks="default"`, beta `server-side-fallback-2026-07-01`) for models
   that support it (`LLM_ANTHROPIC_FALLBACKS=true`). The served model (`response.model`) is
   recorded next to the requested one. A `refusal` stop reason is recorded as status `refused`.
3. **Guards on every gateway call:** AI enabled globally and for the case; `AI_LOCAL_ONLY=true`
   refuses hosted providers (`anthropic`; `openai_compat` unless its base URL is loopback or a
   single-label service name); prompt size <= `AI_MAX_INPUT_CHARS` (413); per-user and per-case
   fixed-window rate limits in Redis (`AI_RATE_LIMIT_PER_MINUTE`, `AI_CASE_RATE_LIMIT_PER_HOUR`,
   429 with `Retry-After`; fail closed with 503 if Redis is down); daily budget from
   `ai_interactions` (`AI_DAILY_TOKEN_BUDGET`, and `AI_DAILY_BUDGET_USD` when prices are
   configured); per-attempt timeout `LLM_TIMEOUT_S`, one retry of transient errors inside an
   overall deadline, SDK retries disabled so the deadline is ours.
4. **Evidence packs.** Records get short ids (`E1..` events, `A1..` alerts, `S1` script input,
   `D1..` decoded layers); the model never sees database ids; the server maps them back.
   Each record is one line of allowlisted fields; every value is sanitized: NFKC, control,
   zero-width and bidi characters removed, newlines shown as `\n`, `<`/`>` replaced by
   fullwidth look-alikes (no tag can be opened or closed), `[E12]`-style tokens rewritten to
   `(E12)` (no forged record ids), per-field cap `AI_MAX_FIELD_CHARS`, record cap
   `AI_MAX_PACK_RECORDS`. Instructions live only in the system prompt; evidence and the analyst's
   question live only in `<evidence>` / `<question>` blocks of the user message, which the system
   prompt declares untrusted data. The model gets no tools.
5. **Injection heuristics** (`app/ai/sanitize.py`) flag instruction-like evidence (role markers,
   "ignore previous instructions", verdict-steering phrases, fake JSON verdicts, fake record ids,
   delimiter strings, the same inside base64). Flags are returned as warnings with the record id,
   stored on the interaction, and shown in the UI. Accepting a flagged output needs an explicit
   `acknowledge_warnings: true`.
6. **Validation before acceptance.** Output must parse as JSON (a single fenced block is
   tolerated) and validate against the feature's Pydantic model (`extra="forbid"`, length and
   count caps). Citations: every `cites` id must be in the pack, required statements must carry at
   least one citation, and IPs/hashes/URLs named in a statement must occur in the cited records
   (otherwise an `unsupported_claim` warning). A1: the query must parse with our search grammar.
   On failure the runner retries once with a corrective message listing the problems; then the
   interaction is stored with status `invalid` and cannot be accepted. The service maps short ids
   to UUIDs and re-checks, in SQL, that every cited event/alert exists **in the same case** both
   when the answer is produced and again at accept time (409 `citations_stale` otherwise).
7. **Redaction for hosted providers** (`AI_REDACTION_POLICY`: `none`, `standard` = e-mail
   addresses and secrets (password/token assignments, bearer tokens, AWS access keys, JWTs,
   private-key blocks), `strict` = standard + IP addresses, user names, host names). Values become
   stable placeholders (`[EMAIL_1]`, `[IP_2]` ...); the mapping is kept server-side on the
   interaction and applied back to the output for display. Hashes and technical ids are kept.
   Local providers are not redacted unless `AI_REDACT_LOCAL=true`.
8. **Provenance.** `ai_interactions` gains `status`, `model_served`, `prompt_sha256` (system +
   rendered user message), `input_sha256` (canonical JSON of the pack records and question),
   `output_sha256` (raw provider text), `prompt_text` (the redacted user message as sent, capped
   at 256 KiB), `warnings`, `error`, `started_at`, review fields. The prompt version is
   `<feature>/v<N>+<sha256(system template)[:12]>`, so any template edit changes it.
9. **Review.** `POST /ai/interactions/{id}/review` (`accept`/`reject`, note) needs `ai:use` on
   the case and an open case; it locks the row (`FOR UPDATE`), re-checks it is still unreviewed
   and `valid`, re-validates citations, writes `accepted`, `reviewed_by`, `reviewed_at`,
   `review_note` and an audit record. A DB trigger enforces review-once and valid-only even for
   direct SQL as the app role. Nothing else is written: no alert status, severity, evidence,
   custody or note changes (asserted in tests).
10. **RAG with pgvector.** Chunks = events of one host in a 5-minute window, at most 40 events or
    4000 characters, text rendered with the pack renderer. Default embeddings are a local,
    deterministic feature-hashing embedder (`hashing-v1`, 384 dimensions: word unigrams and
    bigrams + character trigrams, signed hashing, L2-normalized), which needs no model download or
    RAM and keeps tests offline; `EMBEDDING_PROVIDER=ollama|openai_compat` sends texts through the
    gateway instead. `EMBEDDING_DIM` must stay 384 (settings validation; another dimension needs a
    migration). Retrieval is hybrid: HNSW cosine top 40 (`hnsw.iterative_scan=relaxed_order` so
    the case filter does not starve results) + full-text top 40 on the chunk text, fused by
    reciprocal rank; the top `AI_CHAT_TOP_K` chunks' events (reloaded from `events` with the case
    filter, at most `AI_CHAT_MAX_EVENTS`) form the pack. `ai_index_state` records the event count
    and newest `ingested_at` per case; chat rebuilds a stale index first (advisory lock per case,
    state re-checked after the lock). Indexing runs in the API request, capped by
    `AI_INDEX_MAX_EVENTS` (the answer warns when the index is truncated); moving it to a worker
    queue is backlog.
11. **A7 never executes anything.** `app/ai/decode.py` peels base64, PowerShell
    `-EncodedCommand` (UTF-16LE), `FromBase64String` + gzip/deflate streams (bounded: 1 MiB
    output per layer, ratio 100, depth 4), char-code arrays, hex and URL escapes, then extracts
    indicators (URLs, domains, IPs, e-mails, hashes, Windows paths, registry keys; defanged forms
    normalized) and static ATT&CK hints from a reviewed keyword table. The model explains the
    decoded layers; indicators it names that occur in no record are warnings.
12. **Synchronous narrative.** The guide lists the narrative as an async job; with a 150-event
    cap and the gateway deadline it runs in the request like the other features.
13. **Per-case AI switch.** `cases.ai_enabled` (default true), set with
    `PUT /ai/cases/{id}/settings` by a case manager (`case:manage`), audited.
14. **Evaluation offline.** `FixtureProvider` replays the reference responses stored in each
    dataset item (hand-written references, not recordings of a real model); the harness therefore
    measures the pipeline (rendering, validators, citation mapping, decoders, injection defenses)
    offline. `--provider live` runs the same datasets against the configured provider and
    `--record FILE` saves its responses for later offline replays; neither runs in tests or CI.
    The injection suite uses two simulated models from `FakeProvider`: `obedient_outside`
    (follows instructions that appear outside `<evidence>`/`<question>` blocks, like a model that
    respects delimiters) measures the structural defenses; `obedient_anywhere` (follows
    instructions anywhere) measures whether manipulated outputs are rejected or flagged.

## Files and interfaces
| Path | What |
|---|---|
| `backend/app/ai/gateway.py` | `LLMRequest`, `LLMResponse`, `LLMProvider` (Protocol), `AnthropicProvider`, `OpenAICompatProvider`, `OllamaProvider`, `Gateway.complete(req, *, user_key, case_key)`, `Gateway.embed(texts)`, `build_provider(settings)`, `RateLimiter` (Protocol), `RedisRateLimiter`, `MemoryRateLimiter`; errors `AiUnavailableError`, `AiRateLimitedError`, `AiInputTooLargeError`, `AiProviderError` |
| `backend/app/ai/sanitize.py` | `clean_text(value, max_chars)`, `detect_injection(text) -> list[str]` |
| `backend/app/ai/redaction.py` | `Redactor(policy)`: `redact(text)`, `restore(obj)`, `mapping`, `counts` |
| `backend/app/ai/packs.py` | `PackRecord`, `EvidencePack` (`add_event`, `add_alert`, `add_text`, `render()`, `ids`, `ref_of(short_id)`, `warnings`, `input_sha256`), `event_line()` |
| `backend/app/ai/schemas.py` | output models `NlqOutput`, `AlertExplanation`, `Narrative`, `ChatAnswer`, `ScriptExplanation`; `provider_schema(model)` |
| `backend/app/ai/prompts.py` | `PromptTemplate(feature, version, system, tier)`, `TEMPLATES`, `render_user(...)`, `prompt_version(feature)` |
| `backend/app/ai/validators.py` | `parse_output(text, model)`, `collect_cites(obj)`, `check_citations(obj, pack, required)`, `CitationReport` |
| `backend/app/ai/runner.py` | `FeatureRunner.run(spec, pack, extra) -> RunOutcome` (render, redact, call, validate, one corrective retry) |
| `backend/app/ai/decode.py` | `analyze(text) -> ScriptAnalysis` (layers, indicators, techniques) |
| `backend/app/ai/embeddings.py` | `HashingEmbedder(dim=384)`, `Embedder` protocol |
| `backend/app/ai/rag.py` | `build_chunks(events)`, `rrf(rankings)` (pure) |
| `backend/app/ai/fake.py` | `FakeProvider(mode)`, `FixtureProvider(responses)` |
| `backend/app/ai/eval/` | `harness.py` (`run_suite(name, provider)` -> metrics + targets), `__main__.py`, `datasets/{nlq,alerts,narrative,chat,scripts,injection}.json` |
| `backend/app/services/ai.py` | `AiService`: `status`, `nlq`, `explain_alert`, `narrative`, `chat`, `explain_script`, `list_interactions`, `get_interaction`, `review`, `feedback`, `set_case_ai` |
| `backend/app/services/ai_index.py` | `AiIndexService`: `state`, `ensure_fresh`, `rebuild`, `retrieve` |
| `backend/app/api/v1/ai.py`, `backend/app/schemas/ai.py` | routes and API schemas |
| `backend/app/search/language.py` | new field `id` (uuid) |
| `backend/alembic/versions/0009_ai.py`, `backend/app/db/models/ai.py`, `cases.py` | schema below |
| `backend/app/config.py`, `.env.example`, `infra/compose.yaml` | settings below |
| `frontend/src/features/ai/*` | `AiTab`, `AiResultCard`, `Citations`, alert panel; API client + types |
| `docs/ai.md` | features, providers, safety model, eval harness, limits |
| `scripts/phase7-smoke.py`, `scripts/verify-phase7.sh` | live smoke and verification |

## Data model changes (migration 0009)
* `ai_interactions` + `status` (`valid|invalid|refused|error`), `model_served`, `prompt_sha256`,
  `input_sha256`, `output_sha256` (CHAR(64)), `prompt_text`, `warnings` JSONB, `error`,
  `started_at`, `reviewed_by` (FK users), `reviewed_at`, `review_note`; checks on `status` and
  `feedback IN (-1,0,1)`; indexes `(case_id, created_at)`, `(user_id, created_at)`.
  Trigger `ai_interactions_guard`: only `accepted`, `reviewed_by`, `reviewed_at`, `review_note`,
  `feedback` may change; `accepted` may be set once and only when `status = 'valid'`.
  App role: SELECT, INSERT, UPDATE of those five columns; no DELETE/TRUNCATE.
* `event_chunks` + `host`, `ts_start`, `ts_end`, `embedding_model`, `content_sha256`; index
  `(case_id)`. App role: SELECT, INSERT, DELETE (derived data, rebuilt), no UPDATE/TRUNCATE.
* `ai_index_state` (`case_id` PK/FK, `built_at`, `event_count`, `max_ingested_at`, `chunk_count`,
  `embedding_model`, `truncated`). App role: SELECT, INSERT, UPDATE; no DELETE/TRUNCATE.
* `cases.ai_enabled BOOLEAN NOT NULL DEFAULT true`.

## API changes
| Method | Path | Body | Access |
|---|---|---|---|
| GET | `/ai/status` | - | authenticated |
| POST | `/ai/nlq` | `{case_id, question}` | `ai:use` on case |
| POST | `/ai/alerts/{aid}/explain` | - | `ai:use` |
| POST | `/ai/cases/{id}/narrative` | `{start?, end?, host?}` | `ai:use` |
| POST | `/ai/cases/{id}/chat` | `{question}` | `ai:use` |
| POST | `/ai/script/explain` | `{case_id, text? , event_id?}` | `ai:use` |
| GET/POST | `/ai/cases/{id}/index` | - | read / `ai:use` |
| PUT | `/ai/cases/{id}/settings` | `{ai_enabled}` | `case:manage` |
| GET | `/ai/interactions` | `?case_id&feature&limit&offset` | case read, or `audit:view` without case |
| GET | `/ai/interactions/{iid}` | - | case read |
| POST | `/ai/interactions/{iid}/review` | `{decision, note?, acknowledge_warnings?}` | `ai:use` |
| POST | `/ai/interactions/{iid}/feedback` | `{value: -1/0/1}` | `ai:use` |

Feature responses: `{interaction: {id, feature, status, provider, model, model_served,
prompt_version, created_at, latency_ms, tokens, warnings, accepted}, output, citations:
{short_id: {kind, id, ts, summary}}, ...feature extras}` (A1 adds `query_valid`; A5 adds
`index`; A7 adds the deterministic `analysis`). Errors: 403 (no `ai:use`), 404 (other case),
409 (case closed / AI disabled for the case / citations stale / already reviewed / not valid),
413, 422, 429, 502 (provider), 503 (AI off / not configured / limiter down).

## Settings (new, `.env.example`)
`LLM_PROVIDER=anthropic`, `LLM_MODEL_FAST=claude-haiku-4-5-20251001`,
`LLM_MODEL_STRONG=claude-sonnet-5-5`, `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_TIMEOUT_S=120`,
`LLM_MAX_RETRIES=1`, `LLM_EFFORT` (unset), `LLM_ANTHROPIC_FALLBACKS=true`,
`LLM_PRICE_INPUT_PER_MTOK` / `LLM_PRICE_OUTPUT_PER_MTOK` (unset), `AI_MAX_TOKENS=8000`,
`AI_MAX_INPUT_CHARS=120000`, `AI_MAX_FIELD_CHARS=512`, `AI_MAX_PACK_RECORDS=150`,
`AI_RATE_LIMIT_PER_MINUTE=10`, `AI_CASE_RATE_LIMIT_PER_HOUR=200`, `AI_DAILY_TOKEN_BUDGET=2000000`,
`AI_REDACT_LOCAL=false`, `EMBEDDING_PROVIDER=hashing`, `EMBEDDING_MODEL=hashing-v1`,
`AI_INDEX_MAX_EVENTS=200000`, `AI_CHAT_TOP_K=8`, `AI_CHAT_MAX_EVENTS=120` (plus the existing
`ENABLE_AI`, `AI_LOCAL_ONLY`, `AI_REDACTION_POLICY`, `AI_DAILY_BUDGET_USD`, `EMBEDDING_DIM`).

## Test plan
* Unit (no Docker, no network): sanitizer (control/zero-width/bidi, delimiter and id forging,
  truncation), injection heuristics (30+ phrasings incl. base64), redaction policies and restore,
  pack rendering golden, schema/citation validators (fabricated ids, missing cites, unsupported
  claims, fenced JSON, extra keys), runner retry, prompt versions, decoder (encoded commands,
  gzip bombs, depth caps, char codes, defanged indicators), hashing embedder, chunking, RRF;
  gateway with mocked transports for Anthropic (request body: `output_config`, no temperature,
  fallbacks beta, explicit key), OpenAI-compatible and Ollama; local-only, size cap, rate limit,
  deadline/timeout, refusal, missing key; import-boundary test; settings validation; eval
  harness targets on every dataset.
* Injection suite (unit, `app/ai/eval/datasets/injection.json`, 30 samples: instructions, fake
  JSON, fake ids, delimiter breaking, zero-width/bidi tricks, base64-hidden text): ASR 0% with
  the delimiter-respecting model; with the obey-anywhere model every manipulated output is
  rejected or flagged; warnings raised for every hostile sample.
* Integration (compose Postgres, fake provider): every feature end to end through the API;
  citations map to real ids of the same case; fabricated ids rejected (scripted provider); an
  event from another case can never enter a pack; viewer/auditor 403, outsider 404; AI disabled
  per case -> 409; accept/reject once with a lock and audit row, invalid output cannot be
  accepted, stale citations 409, concurrent accepts -> exactly one wins; AI actions never change
  alerts/evidence/custody; RAG index build, staleness after new events, retrieval scoped to the
  case; rate limit 429; app-role grants and trigger denials; migration 0009 round trip.
* Live: `scripts/phase7-smoke.py` against the compose stack started with `ENABLE_AI=true
  LLM_PROVIDER=fake`: each feature, review, RBAC, hostile evidence warning, index + chat,
  offline eval run inside the API image.

## Acceptance criteria (executable)
1. `pytest tests/unit/test_ai_*.py` (includes the eval targets: citation validity of accepted
   outputs 100%, injection ASR 0%, NL query validity >= 95% on the fixtures, script indicator
   recall >= 90% and precision >= 90%).
2. `python -m app.ai.eval --suite all` exits 0 and prints the metrics.
3. `pytest tests/integration/test_ai.py tests/integration/test_migrations.py`.
4. App role denied: DELETE/TRUNCATE `ai_interactions`, UPDATE of `ai_interactions.output`,
   `.model`, `.status`, `.prompt_text`; UPDATE `event_chunks`; DELETE `ai_index_state`.
5. Live: `scripts/phase7-smoke.py` prints `PHASE 7 SMOKE PASSED`.
6. Earlier phases: collector checks, Phase 1-6 smokes, migrations round trip, backend
   lint/format/type/bandit/tests, frontend lint/typecheck/tests/build.

## Verification command
```bash
bash scripts/verify-phase7.sh
```
