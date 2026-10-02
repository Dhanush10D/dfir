"""LLM gateway (guide 13.3): the ONLY module that sends data to a model.

* Providers: :class:`AnthropicProvider` (official SDK, structured outputs), :class:`OllamaProvider`
  and :class:`OpenAICompatProvider` (``httpx2``). Offline providers live in :mod:`app.ai.fake`.
* :class:`Gateway` enforces, on every call: AI enabled, ``AI_LOCAL_ONLY``, prompt size, per-user
  and per-case rate limits, a per-attempt timeout plus an overall deadline (the call runs in a
  bounded thread pool, so a stalled connection cannot hold the request past the deadline), and
  one retry of transient errors. SDK-internal retries are off so the deadline is ours.
* Keys and model ids come from settings; the key is passed explicitly, so ambient
  ``ANTHROPIC_*`` variables or CLI profiles are never used.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
import urllib.parse
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Protocol, cast

import anthropic
import httpx2
import structlog
from redis import Redis
from redis.exceptions import RedisError

from app.ai.llm import (
    AiInputTooLargeError,
    AiProviderError,
    AiRateLimitedError,
    AiUnavailableError,
    EmbeddingProvider,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    ProviderError,
)
from app.ai.redaction import Policy, Redactor
from app.config import Settings

log = structlog.stdlib.get_logger("dfirbench.ai.gateway")

ANTHROPIC_DEFAULT_URL = "https://api.anthropic.com"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
# Models that accept the server-side refusal fallback ("default" form).
FALLBACK_MODELS = frozenset(
    {"claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5", "claude-fable-5-1"}
)
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_ERROR_CHARS = 300
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ai-gateway")


def _short(text: object) -> str:
    s = str(text).replace("\n", " ")
    return s if len(s) <= MAX_ERROR_CHARS else s[: MAX_ERROR_CHARS - 1] + "…"


def is_local_url(url: str | None) -> bool:
    """Loopback address or a single-label host (a compose service name such as ``ollama``)."""
    if not url:
        return False
    host = urllib.parse.urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    if "." not in host and ":" not in host and host:
        # A compose service name, but not a numeric literal: resolvers read "134744072" or
        # "0x08080808" as an IPv4 address (8.8.8.8).
        return not re.fullmatch(r"(0x[0-9a-f]+|[0-9]+)", host, re.IGNORECASE)
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ------------------------------------------------------------------------------ providers


class AnthropicProvider:
    """Anthropic Messages API with structured outputs (``output_config.format``)."""

    name = "anthropic"
    hosted = True

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        effort: str | None = None,
        fallbacks: bool = True,
        http_client: httpx2.Client | None = None,
    ) -> None:
        self.effort = effort
        self.fallbacks = fallbacks
        self._client = anthropic.Anthropic(
            api_key=api_key,
            base_url=base_url or ANTHROPIC_DEFAULT_URL,
            max_retries=0,
            http_client=http_client,
        )

    def _params(self, req: LLMRequest, model: str) -> dict[str, Any]:
        output_config: dict[str, Any] = {}
        if req.schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": req.schema}
        if self.effort and not model.startswith("claude-haiku"):
            output_config["effort"] = self.effort
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": req.max_tokens,
            "system": req.system,
            "messages": [dict(m) for m in req.messages],
        }
        if output_config:
            params["output_config"] = output_config
        return params

    def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse:
        params = self._params(req, model)
        try:
            if self.fallbacks and model in FALLBACK_MODELS:
                msg: Any = self._client.beta.messages.create(
                    **params, betas=[FALLBACK_BETA], fallbacks="default", timeout=timeout_s
                )
            else:
                msg = self._client.messages.create(**params, timeout=timeout_s)
        except (anthropic.APITimeoutError, anthropic.APIConnectionError) as exc:
            raise ProviderError(f"anthropic: {type(exc).__name__}", transient=True) from exc
        except anthropic.APIStatusError as exc:
            transient = exc.status_code == 429 or exc.status_code >= 500
            # The provider's error body stays in the server log, never in stored/returned errors.
            log.warning(
                "ai_provider_http_error",
                provider=self.name,
                status=exc.status_code,
                body=_short(getattr(exc, "message", "")),
            )
            raise ProviderError(
                f"anthropic: HTTP {exc.status_code}", transient=transient, status=exc.status_code
            ) from exc
        except anthropic.AnthropicError as exc:
            raise ProviderError(f"anthropic: {type(exc).__name__}", transient=False) from exc
        text = "".join(
            getattr(block, "text", "")
            for block in msg.content
            if getattr(block, "type", "") == "text"
        )
        usage = getattr(msg, "usage", None)
        return LLMResponse(
            text=text,
            model=str(getattr(msg, "model", model)),
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
            stop_reason=getattr(msg, "stop_reason", None),
        )


class _HttpProvider:
    name = "http"

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.hosted = not is_local_url(base_url)
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = httpx2.Client(
            headers=headers, follow_redirects=False, trust_env=False, transport=transport
        )

    def _post(self, path: str, body: dict[str, Any], timeout_s: float) -> dict[str, Any]:
        try:
            resp = self._http.post(self.base_url + path, json=body, timeout=timeout_s)
        except httpx2.TimeoutException as exc:
            raise ProviderError(f"{self.name}: timeout", transient=True) from exc
        except httpx2.TransportError as exc:
            raise ProviderError(f"{self.name}: {type(exc).__name__}", transient=True) from exc
        if resp.status_code >= 400:
            transient = resp.status_code == 429 or resp.status_code >= 500
            log.warning(
                "ai_provider_http_error",
                provider=self.name,
                status=resp.status_code,
                body=_short(resp.text),
            )
            raise ProviderError(
                f"{self.name}: HTTP {resp.status_code}",
                transient=transient,
                status=resp.status_code,
            )
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ProviderError(f"{self.name}: response too large", transient=False)
        try:
            data = resp.json()
        except ValueError as exc:
            raise ProviderError(f"{self.name}: response is not JSON", transient=False) from exc
        if not isinstance(data, dict):
            raise ProviderError(f"{self.name}: unexpected response", transient=False)
        return data


class OpenAICompatProvider(_HttpProvider):
    """``POST {base}/chat/completions`` with a JSON-schema ``response_format``; embeddings via
    ``POST {base}/embeddings`` (base usually ends in ``/v1``)."""

    name = "openai_compat"

    def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse:
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": req.system}, *req.messages],
            "max_tokens": req.max_tokens,
            "temperature": 0,
        }
        if req.schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": req.feature, "schema": req.schema, "strict": True},
            }
        data = self._post("/chat/completions", body, timeout_s)
        try:
            choice = data["choices"][0]
            text = choice["message"].get("content") or ""
            reason = choice.get("finish_reason")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ProviderError("openai_compat: unexpected response", transient=False) from exc
        usage = data.get("usage") or {}
        return LLMResponse(
            text=str(text),
            model=str(data.get("model") or model),
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            stop_reason="max_tokens" if reason == "length" else reason,
        )

    def embed(self, texts: list[str], *, model: str, timeout_s: float) -> list[list[float]]:
        data = self._post("/embeddings", {"model": model, "input": texts}, timeout_s)
        try:
            return [list(map(float, item["embedding"])) for item in data["data"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError("openai_compat: bad embeddings response", transient=False) from exc


class OllamaProvider(_HttpProvider):
    """``POST {base}/api/chat`` with ``format=<schema>``; ``POST {base}/api/embed``."""

    name = "ollama"

    def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse:
        body: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "system", "content": req.system}, *req.messages],
            "stream": False,
            "options": {"temperature": 0, "num_predict": req.max_tokens},
        }
        if req.schema is not None:
            body["format"] = req.schema
        data = self._post("/api/chat", body, timeout_s)
        message = data.get("message")
        if not isinstance(message, dict):
            raise ProviderError("ollama: unexpected response", transient=False)
        reason = data.get("done_reason")
        return LLMResponse(
            text=str(message.get("content") or ""),
            model=str(data.get("model") or model),
            input_tokens=data.get("prompt_eval_count"),
            output_tokens=data.get("eval_count"),
            stop_reason="max_tokens" if reason == "length" else reason,
        )

    def embed(self, texts: list[str], *, model: str, timeout_s: float) -> list[list[float]]:
        data = self._post("/api/embed", {"model": model, "input": texts}, timeout_s)
        try:
            return [list(map(float, v)) for v in data["embeddings"]]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError("ollama: bad embeddings response", transient=False) from exc


def build_provider(settings: Settings) -> LLMProvider:
    """The configured chat provider (raises AiUnavailableError when misconfigured)."""
    kind = settings.llm_provider
    key = settings.llm_api_key.get_secret_value() if settings.llm_api_key else None
    if kind == "fake":
        from app.ai.fake import FakeProvider

        return FakeProvider()
    if kind == "anthropic":
        if not key:
            raise AiUnavailableError("The AI provider is not configured (LLM_API_KEY is not set).")
        return AnthropicProvider(
            api_key=key,
            base_url=settings.llm_base_url,
            effort=settings.llm_effort,
            fallbacks=settings.llm_anthropic_fallbacks,
        )
    if not settings.llm_base_url:
        raise AiUnavailableError(f"LLM_BASE_URL is required for LLM_PROVIDER={kind}.")
    if kind == "ollama":
        return OllamaProvider(base_url=settings.llm_base_url, api_key=key)
    return OpenAICompatProvider(base_url=settings.llm_base_url, api_key=key)


def build_embedding_provider(settings: Settings) -> EmbeddingProvider | None:
    """None = local hashing embeddings (no provider call)."""
    if settings.embedding_provider == "hashing":
        return None
    if not settings.embedding_base_url:
        raise AiUnavailableError("EMBEDDING_BASE_URL is required for remote embeddings.")
    key = settings.embedding_api_key.get_secret_value() if settings.embedding_api_key else None
    if settings.embedding_provider == "ollama":
        return OllamaProvider(base_url=settings.embedding_base_url, api_key=key)
    return OpenAICompatProvider(base_url=settings.embedding_base_url, api_key=key)


# ------------------------------------------------------------------------------ rate limits


class RateLimiter(Protocol):
    def hit(self, user_key: str, case_key: str | None) -> None:
        """Count one call; raise AiRateLimitedError when a window is full."""


class MemoryRateLimiter:
    """Fixed windows in memory (tests, single-process tools)."""

    def __init__(
        self, per_minute: int, per_hour: int, clock: Callable[[], float] = time.time
    ) -> None:
        self.per_minute = per_minute
        self.per_hour = per_hour
        self.clock = clock
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def hit(self, user_key: str, case_key: str | None) -> None:
        now = self.clock()
        with self._lock:
            checks = [(f"u:{user_key}:{int(now // 60)}", self.per_minute, 60 - int(now % 60))]
            if case_key:
                checks.append(
                    (f"c:{case_key}:{int(now // 3600)}", self.per_hour, 3600 - int(now % 3600))
                )
            for key, limit, retry in checks:
                if self._counts.get(key, 0) >= limit:
                    raise AiRateLimitedError(
                        "AI rate limit reached; try again later.", max(retry, 1)
                    )
            for key, _, _ in checks:
                self._counts[key] = self._counts.get(key, 0) + 1


class RedisRateLimiter:
    """Fixed windows in Redis (shared by all API processes). Fails closed when Redis is down."""

    def __init__(
        self, redis: Redis, per_minute: int, per_hour: int, clock: Callable[[], float] = time.time
    ) -> None:
        self.redis = redis
        self.per_minute = per_minute
        self.per_hour = per_hour
        self.clock = clock

    def hit(self, user_key: str, case_key: str | None) -> None:
        now = self.clock()
        windows = [
            (f"dfir:ai:rl:u:{user_key}:{int(now // 60)}", 120, self.per_minute, 60 - int(now % 60))
        ]
        if case_key:
            windows.append(
                (
                    f"dfir:ai:rl:c:{case_key}:{int(now // 3600)}",
                    7200,
                    self.per_hour,
                    3600 - int(now % 3600),
                )
            )
        try:
            pipe = self.redis.pipeline()
            for key, ttl, _, _ in windows:
                pipe.incr(key)
                pipe.expire(key, ttl)
            results = pipe.execute()
        except RedisError as exc:
            raise AiUnavailableError("The AI rate limiter is unavailable.") from exc
        for i, (_, _, limit, retry) in enumerate(windows):
            if int(results[2 * i]) > limit:
                raise AiRateLimitedError("AI rate limit reached; try again later.", max(retry, 1))


# ------------------------------------------------------------------------------ gateway


@dataclass(frozen=True)
class GatewayConfig:
    enabled: bool
    local_only: bool
    model_fast: str
    model_strong: str
    max_input_chars: int
    timeout_s: float
    max_retries: int
    embedding_model: str
    redaction_policy: str = "none"  # applied to texts sent to a hosted embedding provider
    redact_local: bool = False
    max_embed_batch_chars: int = 2_000_000

    @classmethod
    def from_settings(cls, s: Settings) -> GatewayConfig:
        return cls(
            enabled=s.enable_ai,
            local_only=s.ai_local_only,
            model_fast=s.llm_model_fast,
            model_strong=s.llm_model_strong,
            max_input_chars=s.ai_max_input_chars,
            timeout_s=s.llm_timeout_s,
            max_retries=s.llm_max_retries,
            embedding_model=s.embedding_model,
            redaction_policy=s.ai_redaction_policy,
            redact_local=s.ai_redact_local,
        )


@dataclass(frozen=True)
class CallStats:
    model_requested: str
    latency_ms: int
    attempts: int


class Gateway:
    def __init__(
        self,
        provider: LLMProvider,
        cfg: GatewayConfig,
        limiter: RateLimiter,
        *,
        embedder: EmbeddingProvider | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.provider = provider
        self.cfg = cfg
        self.limiter = limiter
        self.embedder = embedder
        self.clock = clock
        self.sleep = sleep

    @property
    def provider_name(self) -> str:
        return self.provider.name

    @property
    def hosted(self) -> bool:
        return self.provider.hosted

    def model_for(self, tier: str) -> str:
        return self.cfg.model_fast if tier == "fast" else self.cfg.model_strong

    def check_available(self) -> None:
        if not self.cfg.enabled:
            raise AiUnavailableError("AI features are disabled (ENABLE_AI=false).")
        if self.cfg.local_only and self.provider.hosted:
            raise AiUnavailableError(
                f"AI_LOCAL_ONLY is set and provider '{self.provider.name}' is hosted."
            )

    def _call_with_deadline(self, fn: Callable[[float], Any]) -> tuple[Any, int]:
        """Run ``fn(timeout)`` with retries of transient errors inside one overall deadline."""
        deadline = self.clock() + self.cfg.timeout_s * (self.cfg.max_retries + 1)
        attempt = 0
        while True:
            attempt += 1
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise AiProviderError("The AI provider did not answer in time.")
            per_try = min(self.cfg.timeout_s, remaining)
            future = _EXECUTOR.submit(fn, per_try)
            try:
                return future.result(timeout=per_try + 1.0), attempt
            except FutureTimeout as exc:
                future.cancel()
                err: ProviderError = ProviderError("deadline exceeded", transient=True)
                err.__cause__ = exc
            except ProviderError as exc:
                err = exc
            log.warning(
                "ai_provider_error",
                provider=self.provider.name,
                attempt=attempt,
                transient=err.transient,
                error=_short(err),
            )
            if not err.transient or attempt > self.cfg.max_retries:
                # Generic message only (status code, if any): provider/error details stay in the
                # server log above, never in the API response or ai_interactions.error.
                reason = (
                    f"HTTP {err.status}"
                    if err.status
                    else ("temporarily unavailable" if err.transient else "error")
                )
                raise AiProviderError(f"The AI provider call failed ({reason}).") from err
            self.sleep(min(1.0 * attempt, max(deadline - self.clock(), 0)))

    def complete(
        self, req: LLMRequest, *, user_key: str, case_key: str | None
    ) -> tuple[LLMResponse, CallStats]:
        self.check_available()
        size = req.size_chars
        if size > self.cfg.max_input_chars:
            raise AiInputTooLargeError(size, self.cfg.max_input_chars)
        self.limiter.hit(user_key, case_key)
        model = self.model_for(req.tier)
        start = self.clock()
        response, attempts = self._call_with_deadline(
            lambda t: self.provider.complete(req, model=model, timeout_s=t)
        )
        latency = int((self.clock() - start) * 1000)
        return response, CallStats(model, latency, attempts)

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Remote embeddings (only when EMBEDDING_PROVIDER is not ``hashing``)."""
        if self.embedder is None:
            raise AiUnavailableError("No remote embedding provider is configured.")
        if self.cfg.local_only and self.embedder.hosted:
            raise AiUnavailableError("AI_LOCAL_ONLY is set and the embedding provider is hosted.")
        embedder = self.embedder
        longest = max((len(t) for t in texts), default=0)
        if longest > self.cfg.max_input_chars:
            raise AiInputTooLargeError(longest, self.cfg.max_input_chars)
        total = sum(len(t) for t in texts)
        if total > self.cfg.max_embed_batch_chars:
            raise AiInputTooLargeError(total, self.cfg.max_embed_batch_chars)
        if embedder.hosted or self.cfg.redact_local:
            # Same redaction as prompts; placeholders are never restored for vectors.
            redactor = Redactor(cast(Policy, self.cfg.redaction_policy))
            texts = [redactor.redact(t) for t in texts]
        vectors, _ = self._call_with_deadline(
            lambda t: embedder.embed(texts, model=self.cfg.embedding_model, timeout_s=t)
        )
        return list(vectors)
