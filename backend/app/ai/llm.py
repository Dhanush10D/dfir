"""Provider-neutral request/response types, the provider protocol and AI errors (no network I/O).

The classes that talk to a model live only in :mod:`app.ai.gateway`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from app.core.exceptions import AppError

Tier = Literal["fast", "strong"]


@dataclass(frozen=True)
class LLMRequest:
    feature: str
    tier: Tier
    system: str
    messages: tuple[dict[str, str], ...]  # {"role": "user"|"assistant", "content": str}
    schema: dict[str, Any] | None
    max_tokens: int

    @property
    def size_chars(self) -> int:
        return len(self.system) + sum(len(m["content"]) for m in self.messages)


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str  # model that served the request
    input_tokens: int | None = None
    output_tokens: int | None = None
    stop_reason: str | None = None  # end_turn | max_tokens | refusal | ...
    extra: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    name: str
    hosted: bool  # sends data off this deployment (AI_LOCAL_ONLY refuses it)

    def complete(self, req: LLMRequest, *, model: str, timeout_s: float) -> LLMResponse: ...


class EmbeddingProvider(Protocol):
    name: str
    hosted: bool

    def embed(self, texts: list[str], *, model: str, timeout_s: float) -> list[list[float]]: ...


class ProviderError(Exception):
    """A provider call failed. ``transient`` errors may be retried within the deadline."""

    def __init__(self, message: str, *, transient: bool, status: int | None = None) -> None:
        super().__init__(message)
        self.transient = transient
        self.status = status


# ------------------------------------------------------------------ errors mapped to HTTP


class AiUnavailableError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__("ai_unavailable", message, 503)


class AiDisabledForCaseError(AppError):
    def __init__(self) -> None:
        super().__init__("ai_disabled", "AI features are switched off for this case.", 409)


class AiRateLimitedError(AppError):
    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(
            "rate_limited",
            message,
            429,
            {"retry_after": retry_after},
            headers={"Retry-After": str(retry_after)},
        )


class AiInputTooLargeError(AppError):
    def __init__(self, size: int, limit: int) -> None:
        super().__init__(
            "ai_input_too_large",
            f"The prompt would be {size} characters (limit {limit}); narrow the request.",
            413,
            {"size": size, "limit": limit},
        )


class AiProviderError(AppError):
    def __init__(self, message: str, *, interaction_id: str | None = None) -> None:
        details = {"interaction_id": interaction_id} if interaction_id else {}
        super().__init__("ai_provider_error", message, 502, details)
