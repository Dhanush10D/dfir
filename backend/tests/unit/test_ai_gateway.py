"""Phase 7 unit tests: providers (mocked HTTP transports, never the network), gateway guards
(enabled, local-only, size, rate limits, deadline, retries), provider construction."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import anthropic
import httpx2
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from app.ai.fake import FakeProvider
from app.ai.gateway import (
    FALLBACK_BETA,
    AnthropicProvider,
    Gateway,
    GatewayConfig,
    MemoryRateLimiter,
    OllamaProvider,
    OpenAICompatProvider,
    RedisRateLimiter,
    build_embedding_provider,
    build_provider,
    is_local_url,
)
from app.ai.llm import (
    AiInputTooLargeError,
    AiProviderError,
    AiRateLimitedError,
    AiUnavailableError,
    LLMRequest,
    LLMResponse,
    ProviderError,
)
from app.config import Settings

REQ = LLMRequest(
    feature="alert_explain",
    tier="strong",
    system="SYSTEM",
    messages=({"role": "user", "content": "<evidence>\n[E1] x\n</evidence>"},),
    schema={"type": "object", "properties": {}, "additionalProperties": False},
    max_tokens=1000,
)
ANTHROPIC_OK = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5-5",
    "content": [{"type": "text", "text": '{"a": 1}'}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 11, "output_tokens": 7},
}


def settings(**kw: Any) -> Settings:
    return Settings(_env_file=None, **kw)  # type: ignore[arg-type]


class Capture:
    def __init__(self, responses: list[httpx2.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        return self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]

    def body(self, i: int = 0) -> dict[str, Any]:
        return dict(json.loads(self.requests[i].content))


def anthropic_provider(cap: Capture, **kw: Any) -> AnthropicProvider:
    client = anthropic.DefaultHttpxClient(transport=httpx2.MockTransport(cap))
    return AnthropicProvider(api_key="sk-test-key", http_client=client, **kw)


def gateway(provider: Any, *, retries: int = 1, timeout: float = 5.0, **cfg: Any) -> Gateway:
    base = {
        "enabled": True,
        "local_only": False,
        "model_fast": "claude-haiku-4-5-20251001",
        "model_strong": "claude-sonnet-5-5",
        "max_input_chars": 100_000,
        "timeout_s": timeout,
        "max_retries": retries,
        "embedding_model": "hashing-v1",
    }
    base.update(cfg)
    return Gateway(
        provider, GatewayConfig(**base), MemoryRateLimiter(100, 100), sleep=lambda _: None
    )


# ------------------------------------------------------------------ Anthropic


def test_anthropic_request_uses_structured_outputs_fallbacks_and_explicit_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "ambient-key-must-not-be-used")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://ambient.invalid")
    cap = Capture([httpx2.Response(200, json=ANTHROPIC_OK)])
    provider = anthropic_provider(cap, effort="low")
    resp = provider.complete(REQ, model="claude-sonnet-5-5", timeout_s=5)
    assert resp == LLMResponse('{"a": 1}', "claude-sonnet-5-5", 11, 7, "end_turn")
    req = cap.requests[0]
    assert str(req.url).startswith("https://api.anthropic.com/v1/messages")
    assert req.headers["x-api-key"] == "sk-test-key"
    assert FALLBACK_BETA in req.headers["anthropic-beta"]
    body = cap.body()
    assert body["fallbacks"] == "default"
    assert body["output_config"] == {
        "format": {"type": "json_schema", "schema": REQ.schema},
        "effort": "low",
    }
    assert body["system"] == "SYSTEM" and body["max_tokens"] == 1000
    assert "temperature" not in body and "thinking" not in body


def test_anthropic_haiku_plain_call_without_effort_or_fallbacks() -> None:
    cap = Capture([httpx2.Response(200, json=ANTHROPIC_OK)])
    anthropic_provider(cap, effort="high").complete(
        REQ, model="claude-haiku-4-5-20251001", timeout_s=5
    )
    body = cap.body()
    assert "fallbacks" not in body and "effort" not in body["output_config"]
    assert "anthropic-beta" not in cap.requests[0].headers
    assert body["model"] == "claude-haiku-4-5-20251001"


def test_anthropic_refusal_and_errors_are_classified() -> None:
    refusal = dict(ANTHROPIC_OK, stop_reason="refusal", content=[])
    cap = Capture([httpx2.Response(200, json=refusal)])
    assert anthropic_provider(cap).complete(REQ, model="m", timeout_s=5).stop_reason == "refusal"
    err = {"type": "error", "error": {"type": "rate_limit_error", "message": "slow down"}}
    with pytest.raises(ProviderError) as exc:
        anthropic_provider(Capture([httpx2.Response(429, json=err)])).complete(
            REQ, model="m", timeout_s=5
        )
    assert exc.value.transient and exc.value.status == 429
    bad = {"type": "error", "error": {"type": "invalid_request_error", "message": "bad"}}
    with pytest.raises(ProviderError) as exc:
        anthropic_provider(Capture([httpx2.Response(400, json=bad)])).complete(
            REQ, model="m", timeout_s=5
        )
    assert not exc.value.transient


def test_gateway_retries_transient_once_and_not_fatal() -> None:
    err = {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}
    cap = Capture([httpx2.Response(529, json=err), httpx2.Response(200, json=ANTHROPIC_OK)])
    gw = gateway(anthropic_provider(cap))
    resp, stats = gw.complete(REQ, user_key="u", case_key="c")
    assert resp.text == '{"a": 1}' and stats.attempts == 2 and len(cap.requests) == 2
    assert stats.model_requested == "claude-sonnet-5-5"
    bad = {"type": "error", "error": {"type": "authentication_error", "message": "key"}}
    cap = Capture([httpx2.Response(401, json=bad)])
    with pytest.raises(AiProviderError, match="401"):
        gateway(anthropic_provider(cap)).complete(REQ, user_key="u", case_key="c")
    assert len(cap.requests) == 1


# ------------------------------------------------------------------ HTTP providers


def test_openai_compat_request_and_response() -> None:
    ok = {
        "model": "local-model",
        "choices": [{"message": {"content": '{"a": 1}'}, "finish_reason": "length"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 3},
    }
    cap = Capture([httpx2.Response(200, json=ok)])
    p = OpenAICompatProvider(
        base_url="http://vllm:8000/v1", api_key="k", transport=httpx2.MockTransport(cap)
    )
    assert p.hosted is False  # single-label compose service name
    resp = p.complete(REQ, model="m", timeout_s=5)
    assert resp.stop_reason == "max_tokens" and resp.input_tokens == 5
    req = cap.requests[0]
    assert str(req.url) == "http://vllm:8000/v1/chat/completions"
    assert req.headers["authorization"] == "Bearer k"
    body = cap.body()
    assert body["messages"][0] == {"role": "system", "content": "SYSTEM"}
    assert body["response_format"]["json_schema"]["schema"] == REQ.schema
    assert body["temperature"] == 0
    emb = Capture([httpx2.Response(200, json={"data": [{"embedding": [0.1] * 3}]})])
    p = OpenAICompatProvider(
        base_url="https://api.example.com/v1", transport=httpx2.MockTransport(emb)
    )
    assert p.hosted is True
    assert p.embed(["x"], model="e", timeout_s=5) == [[0.1, 0.1, 0.1]]
    with pytest.raises(ProviderError):
        OpenAICompatProvider(
            base_url="http://x",
            transport=httpx2.MockTransport(Capture([httpx2.Response(200, json={"choices": []})])),
        ).complete(REQ, model="m", timeout_s=5)


def test_ollama_request_errors_and_embeddings() -> None:
    ok = {
        "model": "llama",
        "message": {"content": "{}"},
        "prompt_eval_count": 9,
        "eval_count": 2,
        "done_reason": "stop",
    }
    cap = Capture([httpx2.Response(200, json=ok)])
    p = OllamaProvider(base_url="http://127.0.0.1:11434", transport=httpx2.MockTransport(cap))
    resp = p.complete(REQ, model="llama", timeout_s=5)
    assert resp.input_tokens == 9 and resp.stop_reason == "stop"
    body = cap.body()
    assert body["format"] == REQ.schema and body["stream"] is False
    assert body["options"] == {"temperature": 0, "num_predict": 1000}
    for status, transient in ((503, True), (404, False)):
        cap = Capture([httpx2.Response(status, text="nope")])
        with pytest.raises(ProviderError) as exc:
            OllamaProvider(
                base_url="http://ollama:11434", transport=httpx2.MockTransport(cap)
            ).complete(REQ, model="m", timeout_s=5)
        assert exc.value.transient is transient
    cap = Capture([httpx2.Response(200, text="not json")])
    with pytest.raises(ProviderError, match="not JSON"):
        OllamaProvider(base_url="http://ollama", transport=httpx2.MockTransport(cap)).complete(
            REQ, model="m", timeout_s=5
        )
    cap = Capture([httpx2.Response(200, json={"embeddings": [[1, 2], [3, 4]]})])
    p = OllamaProvider(base_url="http://ollama", transport=httpx2.MockTransport(cap))
    assert p.embed(["a", "b"], model="e", timeout_s=5) == [[1.0, 2.0], [3.0, 4.0]]

    def boom(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("refused", request=request)

    with pytest.raises(ProviderError) as exc:
        OllamaProvider(base_url="http://ollama", transport=httpx2.MockTransport(boom)).complete(
            REQ, model="m", timeout_s=5
        )
    assert exc.value.transient


@pytest.mark.parametrize(
    ("url", "local"),
    [
        ("http://127.0.0.1:11434", True),
        ("http://localhost:8000/v1", True),
        ("http://[::1]:8000", True),
        ("http://ollama:11434", True),
        ("https://api.example.com/v1", False),
        ("http://10.0.0.5:8000", False),
        (None, False),
    ],
)
def test_is_local_url(url: str | None, local: bool) -> None:
    assert is_local_url(url) is local


# ------------------------------------------------------------------ gateway guards


def test_gateway_guards() -> None:
    fake = FakeProvider()
    with pytest.raises(AiUnavailableError, match="ENABLE_AI"):
        gateway(fake, enabled=False).complete(REQ, user_key="u", case_key="c")
    hosted = OpenAICompatProvider(base_url="https://api.example.com/v1")
    with pytest.raises(AiUnavailableError, match="AI_LOCAL_ONLY"):
        gateway(hosted, local_only=True).complete(REQ, user_key="u", case_key="c")
    gateway(fake, local_only=True).check_available()  # local providers are fine
    with pytest.raises(AiInputTooLargeError) as exc:
        gateway(fake, max_input_chars=10).complete(REQ, user_key="u", case_key="c")
    assert exc.value.status_code == 413
    gw = gateway(fake)
    gw.limiter = MemoryRateLimiter(1, 100)
    gw.complete(REQ, user_key="u", case_key="c")
    with pytest.raises(AiRateLimitedError) as rl:
        gw.complete(REQ, user_key="u", case_key="c")
    assert rl.value.status_code == 429 and int(rl.value.headers["Retry-After"]) >= 1
    gw.complete(REQ, user_key="other-user", case_key="c")  # per-user window


def test_gateway_deadline_stops_a_stalled_provider() -> None:
    class Slow:
        name = "slow"
        hosted = False

        def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse:
            time.sleep(3)
            return LLMResponse("{}", model)

    gw = gateway(Slow(), retries=0, timeout=0.2)
    start = time.monotonic()
    with pytest.raises(AiProviderError):
        gw.complete(REQ, user_key="u", case_key="c")
    assert time.monotonic() - start < 2.5


def test_memory_rate_limiter_windows() -> None:
    now = [1000.0]
    lim = MemoryRateLimiter(2, 3, clock=lambda: now[0])
    lim.hit("u", "c")
    lim.hit("u", "c")
    with pytest.raises(AiRateLimitedError):
        lim.hit("u", "c")
    now[0] += 60  # next minute: user window resets; case window (hour) has 1 left
    lim.hit("u", "c")
    with pytest.raises(AiRateLimitedError):
        lim.hit("u2", "c")


class FakePipe:
    def __init__(self, store: dict[str, int], fail: bool) -> None:
        self.store, self.fail, self.ops = store, fail, []  # type: ignore[var-annotated]

    def incr(self, key: str) -> None:
        self.ops.append(("incr", key))

    def expire(self, key: str, ttl: int) -> None:
        self.ops.append(("expire", key))

    def execute(self) -> list[int]:
        if self.fail:
            raise RedisConnectionError("down")
        out = []
        for op, key in self.ops:
            if op == "incr":
                self.store[key] = self.store.get(key, 0) + 1
                out.append(self.store[key])
            else:
                out.append(1)
        return out


class FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.store: dict[str, int] = {}
        self.fail = fail

    def pipeline(self) -> FakePipe:
        return FakePipe(self.store, self.fail)


def test_redis_rate_limiter_counts_and_fails_closed() -> None:
    redis = FakeRedis()
    lim = RedisRateLimiter(redis, 1, 10, clock=lambda: 120.0)  # type: ignore[arg-type]
    lim.hit("u", "c")
    assert sorted(redis.store) == ["dfir:ai:rl:c:c:0", "dfir:ai:rl:u:u:2"]
    with pytest.raises(AiRateLimitedError):
        lim.hit("u", "c")
    with pytest.raises(AiUnavailableError):
        RedisRateLimiter(FakeRedis(fail=True), 1, 1).hit("u", None)  # type: ignore[arg-type]


# ------------------------------------------------------------------ construction


def test_build_provider_and_embeddings() -> None:
    assert isinstance(build_provider(settings(llm_provider="fake")), FakeProvider)
    with pytest.raises(AiUnavailableError, match="LLM_API_KEY"):
        build_provider(settings(llm_provider="anthropic"))
    p = build_provider(settings(llm_provider="anthropic", llm_api_key="sk-x"))
    assert isinstance(p, AnthropicProvider) and p.hosted
    with pytest.raises(AiUnavailableError, match="LLM_BASE_URL"):
        build_provider(settings(llm_provider="ollama"))
    assert isinstance(
        build_provider(settings(llm_provider="ollama", llm_base_url="http://ollama:11434")),
        OllamaProvider,
    )
    assert isinstance(
        build_provider(settings(llm_provider="openai_compat", llm_base_url="http://x/v1")),
        OpenAICompatProvider,
    )
    assert build_embedding_provider(settings()) is None
    with pytest.raises(AiUnavailableError):
        build_embedding_provider(settings(embedding_provider="ollama", embedding_model="m"))
    emb = build_embedding_provider(
        settings(embedding_provider="ollama", embedding_model="m", embedding_base_url="http://o")
    )
    assert isinstance(emb, OllamaProvider)
    cfg = GatewayConfig.from_settings(settings(enable_ai=True, ai_local_only=True))
    assert cfg.enabled and cfg.local_only and cfg.model_strong == "claude-sonnet-5-5"


def test_gateway_embed_guards() -> None:
    gw = gateway(FakeProvider())
    with pytest.raises(AiUnavailableError):
        gw.embed(["x"])
    cap = Capture([httpx2.Response(200, json={"embeddings": [[0.5]]})])
    gw.embedder = OllamaProvider(base_url="http://ollama", transport=httpx2.MockTransport(cap))
    assert gw.embed(["x"]) == [[0.5]]
    hosted: Callable[[], Gateway] = lambda: gateway(FakeProvider(), local_only=True)  # noqa: E731
    g2 = hosted()
    g2.embedder = OpenAICompatProvider(base_url="https://api.example.com/v1")
    with pytest.raises(AiUnavailableError):
        g2.embed(["x"])
