"""RateLimiter & Budget — keep an authorized scan from becoming a DoS.

Three independent brakes, all enforced in the request path:

* **Per-host token bucket** caps requests/second to each host.
* **Global concurrency semaphore** caps simultaneous in-flight requests.
* **Budget** caps total requests and wall-clock time for the whole scan.

On a 429/503 the caller reports it via :meth:`RateLimiter.penalize` which
temporarily drains the bucket (adaptive backoff), so we ease off a struggling
target instead of hammering it.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from .errors import BudgetExceeded


@dataclass
class Budget:
    max_requests: int = 5000
    max_seconds: float = 3600.0
    _used_requests: int = 0
    _started: float = field(default_factory=time.monotonic)

    def spend(self, n: int = 1) -> None:
        if self._used_requests + n > self.max_requests:
            raise BudgetExceeded(
                f"request budget exhausted ({self._used_requests}/{self.max_requests})"
            )
        if time.monotonic() - self._started > self.max_seconds:
            raise BudgetExceeded(f"time budget exhausted ({self.max_seconds}s)")
        self._used_requests += n

    @property
    def used(self) -> int:
        return self._used_requests

    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self._used_requests)


class _TokenBucket:
    def __init__(self, rate: float, burst: float):
        self.rate = rate
        self.capacity = burst
        self.tokens = burst
        self.updated = time.monotonic()
        self.penalty_until = 0.0

    def _refill(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now

    def time_until_token(self) -> float:
        now = time.monotonic()
        if now < self.penalty_until:
            return self.penalty_until - now
        self._refill()
        if self.tokens >= 1:
            return 0.0
        return (1 - self.tokens) / self.rate

    def take(self) -> None:
        self._refill()
        self.tokens -= 1

    def penalize(self, seconds: float) -> None:
        self.penalty_until = max(self.penalty_until, time.monotonic() + seconds)


class RateLimiter:
    def __init__(self, *, per_host_rps: float = 4.0, burst: float = 8.0, max_concurrency: int = 8):
        self._rps = per_host_rps
        self._burst = burst
        self._buckets: dict[str, _TokenBucket] = {}
        self._sem = asyncio.Semaphore(max_concurrency)
        self._lock = asyncio.Lock()

    def _bucket(self, host: str) -> _TokenBucket:
        b = self._buckets.get(host)
        if b is None:
            b = _TokenBucket(self._rps, self._burst)
            self._buckets[host] = b
        return b

    async def acquire(self, host: str) -> None:
        """Block until a request to ``host`` may proceed."""
        await self._sem.acquire()
        try:
            while True:
                async with self._lock:
                    wait = self._bucket(host).time_until_token()
                    if wait <= 0:
                        self._bucket(host).take()
                        return
                await asyncio.sleep(wait)
        except BaseException:
            self._sem.release()
            raise

    def release(self) -> None:
        self._sem.release()

    def penalize(self, host: str, seconds: float = 5.0) -> None:
        self._bucket(host).penalize(seconds)
