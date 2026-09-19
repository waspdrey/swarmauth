"""Distributed usage tracking backed by Redis.

`swarmauth.middleware.UsageTracker` is in-memory and process-local -- correct
for a single verifier process, but a swarm often has many verifier processes
(or machines) enforcing the same token's `max_calls` / `max_amount_usd` /
`rate_limit_per_min`. `RedisUsageTracker` enforces the identical constraint
logic atomically across all of them, using the same duck-typed
`check_and_record(claims, *, amount=0.0)` interface as `UsageTracker`, so it
drops into `swarmauth.guard(..., tracker=...)` unchanged.

Requires the optional `redis` extra: `pip install swarmauth[redis]`.

Design notes
------------
- State is keyed by the token's `jti`, exactly like `UsageTracker`.
- Redis keys are given a TTL instead of being manually cleaned up: since
  every JCT expires within `swarmauth.token.MAX_TTL_SECONDS` (300s) and a
  verifier must independently reject an expired token anyway, there is never
  a legitimate reason to query a jti's usage after that window -- so letting
  Redis expire the key is both correct and avoids unbounded key growth.
- Correctness under concurrent verifiers uses Redis's optimistic-locking
  WATCH/MULTI/EXEC, not a Lua script: all reads used for the constraint
  checks happen before WATCH is committed to a transaction, and all writes
  are queued inside MULTI, so a concurrent modification during the check
  aborts and retries the whole check-and-record rather than applying a
  partial update. This is verified in `tests/test_redis_backend.py` against
  a real `fakeredis` server (no live Redis required to run those tests).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from swarmauth.exceptions import ConstraintViolationError
from swarmauth.token import MAX_TTL_SECONDS, CapabilityClaims

if TYPE_CHECKING:
    import redis as redis_module

try:
    import redis as _redis
except ImportError:
    _redis = None


class RedisUsageTracker:
    """Redis-backed equivalent of `swarmauth.middleware.UsageTracker`.

    Pass any `redis.Redis`-compatible client (a real one, or a test double
    like `fakeredis.FakeStrictRedis()`) -- this class only calls documented
    public redis-py client/pipeline methods.
    """

    def __init__(
        self,
        client: "redis_module.Redis",
        *,
        key_prefix: str = "swarmauth:usage:",
        key_ttl_seconds: int = MAX_TTL_SECONDS + 30,
    ) -> None:
        if _redis is None:
            raise ImportError("RedisUsageTracker requires the 'redis' package: pip install swarmauth[redis]")
        self._redis = client
        self._key_prefix = key_prefix
        self._key_ttl_seconds = key_ttl_seconds

    def _hash_key(self, jti: str) -> str:
        return f"{self._key_prefix}{jti}"

    def _zset_key(self, jti: str) -> str:
        return f"{self._key_prefix}{jti}:calls"

    def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        import time

        constraints = claims.constraints
        hash_key = self._hash_key(claims.jti)
        zset_key = self._zset_key(claims.jti)

        # The `with` block's __exit__ resets the pipeline (unwatch + discard
        # any queued commands) on any exit path, including an exception, so
        # a ConstraintViolationError raised below never leaves a dangling
        # WATCH or a half-built MULTI on the connection.
        with self._redis.pipeline() as pipe:
            while True:
                pipe.watch(hash_key, zset_key)
                now = time.time()

                # Reads only, before MULTI: writing to a watched key here
                # (even a "cleanup" write) would self-invalidate the
                # transaction on every attempt.
                current_calls = int(pipe.hget(hash_key, "calls") or 0)
                current_amount = float(pipe.hget(hash_key, "amount") or 0.0)
                recent_count = 0
                if constraints.rate_limit_per_min is not None:
                    recent_count = pipe.zcount(zset_key, now - 60, "+inf")

                if constraints.max_calls is not None and current_calls + 1 > constraints.max_calls:
                    raise ConstraintViolationError(
                        f"Token {claims.jti} already used {current_calls}/{constraints.max_calls} calls",
                        constraint="max_calls",
                    )
                if constraints.max_amount_usd is not None and current_amount + amount > constraints.max_amount_usd:
                    remaining = constraints.max_amount_usd - current_amount
                    raise ConstraintViolationError(
                        f"Amount {amount} would exceed remaining budget ({remaining:.2f} of {constraints.max_amount_usd})",
                        constraint="max_amount_usd",
                    )
                if constraints.rate_limit_per_min is not None and recent_count + 1 > constraints.rate_limit_per_min:
                    raise ConstraintViolationError(
                        f"Rate limit exceeded: {recent_count}/{constraints.rate_limit_per_min} calls in last 60s",
                        constraint="rate_limit_per_min",
                    )

                pipe.multi()
                pipe.hincrby(hash_key, "calls", 1)
                pipe.hincrbyfloat(hash_key, "amount", amount)
                pipe.zadd(zset_key, {f"{now!r}": now})
                pipe.zremrangebyscore(zset_key, 0, now - 60)
                pipe.expire(hash_key, self._key_ttl_seconds)
                pipe.expire(zset_key, self._key_ttl_seconds)
                try:
                    pipe.execute()
                    return
                except _redis.WatchError:
                    continue
