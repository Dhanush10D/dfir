# AI layer (Phase 7)

dfirbench uses a language model as an assistant, never as an authority (guide 13). Every AI
answer is grounded in the case's own evidence, validated on the server, recorded with its
provenance, and becomes "accepted" only when a person accepts it. Nothing the AI produces changes
evidence, custody, alerts or verdicts.

Spec and decisions: `docs/specs/PHASE-7.md`. Code: `backend/app/ai/`, `backend/app/services/ai.py`,
`backend/app/services/ai_index.py`, `backend/app/api/v1/ai.py`, `frontend/src/features/ai/`.

## Features

| ID | Feature | Endpoint | Model tier | Output (validated) |
|---|---|---|---|---|
| A1 | Natural-language search | `POST /ai/nlq` `{case_id, question}` | fast | `query` (must parse with the search grammar; never SQL), `explanation`, `assumptions` |
| A2 | Alert explanation | `POST /ai/alerts/{id}/explain` | strong | summary, assessment (`likely_malicious`, `suspicious`, `likely_benign`, `insufficient_evidence`), confidence, cited key facts, next steps, ATT&CK candidates, limitations |
| A3 | Attack narrative | `POST /ai/cases/{id}/narrative` `{start?, end?, host?}` | strong | title, summary, timeline entries (time, stage, statement, citations), gaps |
| A5 | Case chat (RAG) | `POST /ai/cases/{id}/chat` `{question}` | strong | `answered` or `insufficient_evidence`, answer, cited key facts |
| A7 | Script/command explanation | `POST /ai/script/explain` `{case_id, text \| event_id}` | strong | summary, risk, behaviors, indicators, ATT&CK candidates, plus the deterministic decoding |

Supporting endpoints: `GET /ai/status`; `GET/POST /ai/cases/{id}/index` (chat index state /
rebuild); `PUT /ai/cases/{id}/settings` `{ai_enabled}` (case managers); `GET /ai/interactions`
(`?case_id=`; without it: `audit:view` only); `GET /ai/interactions/{id}` (includes the redacted
prompt as sent); `POST /ai/interactions/{id}/review` `{decision, note?, acknowledge_warnings?}`;
`POST /ai/interactions/{id}/feedback` `{value: -1|0|1}`.

Who may do what: analysts, leads and admins with the case (`ai:use`) run features and review;
viewers and auditors read the case's AI history; auditors and admins list the AI audit across all
cases; a case outsider gets 404 everywhere.

In the UI: the **AI analyst** case tab (chat, plain-language search, narrative, script
explanation, history) and **Explain with AI** on an alert. Each answer shows an "AI-generated"
badge, validation status, model, prompt version and time, warnings, clickable citations (they open
the cited event in the timeline via the `id:` search field), Accept/Reject, feedback, and
"Show what was sent to the model".

## Request path

```
API -> AiService: case access (404 across cases) + ai:use + open case + AI on for the case
       + daily budget
    -> context from THIS case only (SQL always filtered by case_id)
    -> evidence pack (short ids E1/A1/S1/D1, sanitized one-line records, <evidence> block)
    -> FeatureRunner: versioned prompt -> redaction (hosted providers) -> Gateway -> validators
       -> one corrective retry
    -> server-side check that every cited record exists in the same case
    -> ai_interactions row + audit_log row -> response
```

`app/ai/gateway.py` is the only module that sends data to a model (a unit test fails if
`anthropic`, `httpx2`, `requests`, `socket` or `urllib.request` is imported anywhere else in the
AI code). The gateway enforces, on every call: AI enabled, `AI_LOCAL_ONLY`, prompt size
(`AI_MAX_INPUT_CHARS`, 413), per-user and per-case rate limits in Redis (429 + `Retry-After`;
fails closed with 503 if Redis is down), a per-attempt timeout and one overall deadline (the call
runs in a bounded thread pool), and one retry of transient errors. SDK retries are off.

## Providers and models

| `LLM_PROVIDER` | Transport | Hosted? | Notes |
|---|---|---|---|
| `anthropic` (default) | official SDK `anthropic==1.9.0` | yes | structured outputs (`output_config.format`), no `temperature`, optional `LLM_EFFORT` (not sent to Haiku), server-side refusal fallback (`fallbacks="default"`, beta `server-side-fallback-2026-07-01`) on models that support it; `stop_reason: refusal` is stored as status `refused` |
| `ollama` | `POST {LLM_BASE_URL}/api/chat` with `format=<schema>` | no if the URL is loopback or a compose service name | also embeddings via `/api/embed` |
| `openai_compat` | `POST {LLM_BASE_URL}/chat/completions` with a JSON-schema `response_format` | as above | vLLM, LM Studio, llama.cpp server, hosted APIs |
| `fake` | none (offline) | no | deterministic demo/test provider; refused when `APP_ENV=prod` |

Defaults: `LLM_MODEL_FAST=claude-haiku-4-5-20251001` (A1), `LLM_MODEL_STRONG=claude-sonnet-5-5`
(A2, A3, A5, A7). Model ids are configuration. The API key is `LLM_API_KEY` in the real `.env`
(never committed); it is passed to the SDK explicitly, so ambient `ANTHROPIC_API_KEY`,
`ANTHROPIC_BASE_URL` or CLI profiles are never used. AI is off unless `ENABLE_AI=true`; enabled
without a key, AI endpoints answer 503 `ai_unavailable`.

Minimal real setup (repo-root `.env`, then `docker compose -f infra/compose.yaml --env-file .env up -d`):

```
ENABLE_AI=true
LLM_PROVIDER=anthropic
LLM_API_KEY=<your key>
```

Local-only setup (no data leaves the host): `AI_LOCAL_ONLY=true`, `LLM_PROVIDER=ollama`,
`LLM_BASE_URL=http://ollama:11434`, model ids of models pulled into Ollama.

## Safety model

**Evidence is untrusted input.** Attackers can write text into logs, file names, command lines and
documents. Defenses (guide 13.6, tested by the injection suite):

1. Instructions live only in the system prompt; evidence and the analyst's question live only in
   `<evidence>`, `<question>` and `<context>` data blocks that the system prompt declares untrusted.
2. Every evidence value is sanitized (`app/ai/sanitize.py`): NFKC; control, zero-width and bidi
   characters removed; line breaks shown as `\n` (a record is always one line); `<` and `>`
   replaced by fullwidth look-alikes (no block can be closed or opened from inside the data);
   record-id look-alikes such as `[E12]` rewritten to `(E12)`; per-field and per-pack caps. Only an
   allowlist of fields is sent (never `raw`).
3. Heuristics flag instruction-like evidence (role markers, "ignore previous instructions",
   verdict steering, fake JSON verdicts, fake record ids, delimiter strings, output steering,
   hidden characters, the same inside base64). The flag is shown to the analyst and stored; an
   answer with such a warning can only be accepted with `acknowledge_warnings`.
4. Output must be one JSON object that validates against the feature's schema (extra keys
   forbidden, lengths capped). A1 queries must parse with our own search grammar.
5. Citations: every cited id must be a record of the pack; required statements must cite; IPs,
   hashes and URLs named in a statement must appear in the records it cites (otherwise an
   `unsupported_claim` warning). Short ids are mapped to database ids on the server, which checks
   in SQL that each cited event/alert exists in the same case, at answer time and again at accept
   time (`409 citations_stale`).
6. On a validation failure the model gets one corrective retry; after that the interaction is
   stored as `invalid` and shown as "AI could not produce a verified answer". It cannot be accepted.
7. The model has no tools and no write path. Review writes only the review columns of the
   interaction (row lock, state re-checked under the lock, audit record); a database trigger
   enforces review-once and valid-only even for direct SQL as the app role.

**Privacy.** For hosted providers the prompt is redacted (`AI_REDACTION_POLICY`): `standard` =
e-mail addresses and secrets (private-key blocks, including cut/unterminated ones; password,
token, API-key and secret-access-key assignments in `key=value`, `key: value` and JSON forms,
quoted values with spaces; URL credentials; bearer/basic tokens; AWS key ids; JWTs, including
cut ones); `strict` adds IP addresses and the whole `user`/`host` values of records. Redaction is
applied to every **raw** evidence value (and to the question and context) *before* the value is
sanitized, quoted and truncated for the prompt, so escaping cannot separate a secret from its
key and truncation cannot cut off the end of a block. Values become stable placeholders
(`[EMAIL_1]`); the mapping stays in the database and restores the answer for display. Texts sent
to a hosted embedding provider get the same redaction (per raw value) and a size cap. Regex
redaction is best effort (names inside free text are not recognised). Local providers are not
redacted unless `AI_REDACT_LOCAL=true`. `AI_LOCAL_ONLY=true` refuses hosted providers. AI can be
switched off per case, and an answer is discarded (audited as `ai.<feature>.discarded`) if the
case is closed or AI is switched off while the model is answering. Provider error bodies are only
logged server-side; callers and `ai_interactions.error` get a generic message with the status.

**Provenance** (`ai_interactions`): feature, provider, requested and served model, prompt version
(`<feature>/v<N>+<sha256(system prompt)[:12]>`), input hash (canonical pack + question), prompt
hash, output hash, the redacted prompt as sent (capped at 256 KiB), record references, citations,
warnings, status, error, tokens, latency, cost (when `LLM_PRICE_*` are set), timestamps, reviewer,
review time and note, feedback. The app role cannot delete or rewrite these rows.

**Limits.** `AI_RATE_LIMIT_PER_MINUTE` per user, `AI_CASE_RATE_LIMIT_PER_HOUR` per case,
`AI_DAILY_TOKEN_BUDGET` for all calls per UTC day, `AI_DAILY_BUDGET_USD` when prices are
configured, `AI_MAX_TOKENS` output tokens per call, `LLM_TIMEOUT_S` per attempt.

## Case chat (RAG)

The chat index lives in `event_chunks` (pgvector, HNSW cosine). Chunks are the events of one host
in a 5-minute window (at most 40 events or 4000 characters), rendered with the pack renderer.
Default embeddings are `hashing-v1`: a local, deterministic feature-hashing embedder (word and
bigram and character-trigram features, 384 dimensions). It is lexical, not semantic, but needs no
model download and runs anywhere; `EMBEDDING_PROVIDER=ollama|openai_compat` with
`EMBEDDING_BASE_URL` sends chunk texts through the gateway instead (the model must return 384
dimensions; another size needs a migration). Retrieval is hybrid (vector top 40 + full-text top 40,
reciprocal rank fusion, `AI_CHAT_TOP_K` chunks) and always filtered by case. The events of the
retrieved chunks are reloaded from `events` (case filter again) and packed. `ai_index_state`
records the event count and newest `ingested_at`; a chat on a stale index rebuilds it first (per-case
advisory lock). Indexing runs in the request and is capped by `AI_INDEX_MAX_EVENTS` (the answer
warns when the index is truncated).

## Script explanation (A7)

`app/ai/decode.py` never executes anything. It peels PowerShell `-EncodedCommand`,
`FromBase64String` (with gzip/deflate), long base64 blobs, char-code arrays, hex and URL escapes
(bounded: 1 MiB per layer, ratio 100, depth 4, 12 layers), extracts indicators (URLs, domains,
IPs, e-mails, hashes, Windows paths, registry keys; defanged forms normalized) and static ATT&CK
hints from a reviewed keyword table. The model explains the input (`S1`) and the decoded layers
(`D1`...); indicators it names that do not occur in the cited records are flagged.

## Evaluation harness

```
cd backend
python -m app.ai.eval                      # all suites, offline (fixtures), exits 1 on a miss
python -m app.ai.eval --suite injection --out report.json
python -m app.ai.eval --provider live --record replies.json   # manual only: calls the real model
```

Datasets are packaged in `backend/app/ai/eval/datasets/` and generated by
`backend/tests/fixtures/ai/make_eval_datasets.py`. Their `response` fields are hand-written
reference answers, not recordings of a real model: offline runs measure the pipeline (rendering,
validators, citation mapping, decoder, injection defenses). `--provider live` measures a real
model on the same items; store its report with the prompt versions and model ids it prints.

| Suite | Items | Metrics (target) |
|---|---|---|
| nlq | 50 + 5 bad replies | query validity (>= 95%), AST match with the expected query (>= 90%), bad replies rejected (100%) |
| alerts | 30 labeled + 4 fabricated | assessment accuracy (>= 80%), citation validity of accepted outputs (100%), fabricated citations rejected (100%) |
| narrative | 6 stories | key-event coverage (>= 80%), ordering (100%), citation validity (100%) |
| chat | 10 | answered/insufficient accuracy (>= 90%), citation validity (100%) |
| scripts | 30 | decoder indicator precision and recall (>= 90%), ATT&CK hint recall (>= 80%), valid A7 outputs (100%) |
| injection | 30 adversarial samples | ASR with a delimiter-respecting simulated model (0%), manipulated outputs of an obey-anything model rejected or flagged (100%), warning rate (100%) |

The injection suite has teeth: a unit test disables the sanitizer and checks that the same suite
then reports successful attacks. The offline eval runs in CI and in `scripts/verify-phase7.sh`
(also inside the API image).

## Operations notes

* The dev stack starts with AI off. `scripts/verify-phase7.sh` starts it with `ENABLE_AI=true
  LLM_PROVIDER=fake` for the live smoke (no model, no network).
* A provider error is stored as an `error` interaction and answered with 502 and its id.
* Changing a prompt template changes its prompt version; re-run the eval and keep the report.
* Not in this phase (see `docs/BACKLOG.md`): report drafting and report QA (Phase 8), IOC
  extraction, ATT&CK and playbook suggestions, scikit-learn analytics, background indexing jobs,
  neural embeddings in a `worker-ai` image.
