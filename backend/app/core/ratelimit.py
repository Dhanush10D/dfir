"""Fixed-window rate limits (guide 14.3). Redis in production, memory in tests and tools.

``hit(key, limit, window_s)`` counts one call and raises :class:`RateLimitedError` once the window
is full. The Redis limiter fails closed (:class:`RateLimiterUnavailableError`) when Redis is down.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError


class RateLimitedError(Exception):
    def __init__(self, retry_after_s: int) -> None:
        super().__init__("rate limit reached")
        self.retry_after_s = max(int(retry_after_s), 1)


class RateLimiterUnavailableError(Exception):
    pass


class WindowLimiter(Protocol):
    def hit(self, key: str, limit: int, window_s: int = 60) -> None: ...


class MemoryWindowLimiter:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self.clock = clock
        self._counts: dict[str, int] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_s: int = 60) -> None:
        now = self.clock()
        slot = f"{key}:{int(now // window_s)}"
        with self._lock:
            if self._counts.get(slot, 0) >= limit:
                raise RateLimitedError(window_s - int(now % window_s))
            self._counts[slot] = self._counts.get(slot, 0) + 1


class RedisWindowLimiter:
    def __init__(
        self, redis: Redis, prefix: str = "dfir:rl", clock: Callable[[], float] = time.time
    ) -> None:
        self.redis = redis
        self.prefix = prefix
        self.clock = clock

    def hit(self, key: str, limit: int, window_s: int = 60) -> None:
        now = self.clock()
        slot = f"{self.prefix}:{key}:{int(now // window_s)}"
        try:
            pipe = self.redis.pipeline()
            pipe.incr(slot)
            pipe.expire(slot, window_s * 2)
            count = int(pipe.execute()[0])
        except RedisError as exc:
            raise RateLimiterUnavailableError("the rate limiter is unavailable") from exc
        if count > limit:
            raise RateLimitedError(window_s - int(now % window_s))
