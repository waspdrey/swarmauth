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
- State is keyed by each token's `jti`; delegated calls reserve both parent and child atomically.
- Redis keys are given a TTL instead of being manually cleaned up: since
  every JCT expires within `swarmauth.token.MAX_TTL_SECONDS` (30s) and a
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

import math
import time
from decimal import Decimal
from types import ModuleType
from typing import TYPE_CHECKING, Sequence

from swarmauth.crypto import generate_jti
from swarmauth.exceptions import ConstraintViolationError, TokenExpiredError
from swarmauth.limits import RETENTION_AFTER_EXP_SECONDS
from swarmauth.middleware import _decimal_sum, _decimal_text, _validated_amount
from swarmauth.token import MAX_TTL_SECONDS, CapabilityClaims

if TYPE_CHECKING:
    import redis as redis_module

_redis: "ModuleType | None"
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
        if type(key_ttl_seconds) is not int or key_ttl_seconds < 1:
            raise ValueError("key_ttl_seconds must be a positive integer")
        self._redis = client
        self._key_prefix = key_prefix
        self._key_ttl_seconds = key_ttl_seconds

    def _hash_key(self, jti: str) -> str:
        return f"{self._key_prefix}{jti}"

    def _zset_key(self, jti: str) -> str:
        return f"{self._key_prefix}{jti}:calls"

    def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        self.check_and_record_chain([claims], amount=amount)

    def check_and_record_chain(self, chain: Sequence[CapabilityClaims], *, amount: float = 0.0) -> None:
        """WATCH every parent/child key; reserve all counters in one transaction."""
        amount = _validated_amount(amount)
        if not chain or len({claims.jti for claims in chain}) != len(chain):
            raise ConstraintViolationError("Delegation token IDs must be distinct", constraint="max_calls")
        keys = [(self._hash_key(claims.jti), self._zset_key(claims.jti)) for claims in chain]
        with self._redis.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(*(key for pair in keys for key in pair))  # type: ignore[no-untyped-call]
                    now = time.time()
                    if any(now >= claims.exp + RETENTION_AFTER_EXP_SECONDS for claims in chain):
                        raise TokenExpiredError("Token expired before usage reservation")
                    totals = []
                    for claims, (hash_key, zset_key) in zip(chain, keys, strict=True):
                        limits = claims.constraints
                        calls = int(pipe.hget(hash_key, "calls") or 0)
                        raw_spent = pipe.hget(hash_key, "amount") or b"0"
                        spent = Decimal(raw_spent.decode("ascii") if isinstance(raw_spent, bytes) else str(raw_spent))
                        total = _decimal_sum(spent, amount)
                        totals.append(total)
                        recent = pipe.zcount(zset_key, now - 60, "+inf") if limits.rate_limit_per_min is not None else 0
                        if limits.max_calls is not None and calls + 1 > limits.max_calls:
                            raise ConstraintViolationError("Token call allowance exhausted", constraint="max_calls")
                        if limits.max_amount_usd is not None and total > Decimal(str(limits.max_amount_usd)):
                            raise ConstraintViolationError("Token budget exhausted", constraint="max_amount_usd")
                        if limits.rate_limit_per_min is not None and recent + 1 > limits.rate_limit_per_min:
                            raise ConstraintViolationError("Token rate allowance exhausted", constraint="rate_limit_per_min")
                    pipe.multi()
                    for claims, (hash_key, zset_key), total in zip(chain, keys, totals, strict=True):
                        ttl = max(self._key_ttl_seconds, math.ceil(claims.exp + RETENTION_AFTER_EXP_SECONDS - now))
                        pipe.hincrby(hash_key, "calls", 1)
                        pipe.hset(hash_key, "amount", _decimal_text(total))
                        # Unique member even when concurrent calls share the same clock tick.
                        pipe.zadd(zset_key, {generate_jti(): now})
                        pipe.zremrangebyscore(zset_key, "-inf", f"({now - 60}")
                        pipe.expire(hash_key, ttl)
                        pipe.expire(zset_key, ttl)
                    pipe.execute()
                    return
                except _redis.WatchError:  # type: ignore[union-attr]
                    continue


class RedisRevocationStore:
    """Redis-backed token revocation shared by every verifier process.

    A revoked token ID is stored only through its signed expiry, so the store
    remains bounded without a background cleanup job.
    """

    def __init__(self, client: "redis_module.Redis", *, key_prefix: str = "swarmauth:revoked:") -> None:
        if _redis is None:
            raise ImportError("RedisRevocationStore requires the 'redis' package: pip install swarmauth[redis]")
        self._redis = client
        self._key_prefix = key_prefix

    def revoke(self, jti: str, *, expires_at: int) -> None:
        ttl_seconds = math.ceil(expires_at + RETENTION_AFTER_EXP_SECONDS - time.time())
        if ttl_seconds <= 0:
            return
        key = self._key(jti)
        with self._redis.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)  # type: ignore[no-untyped-call]
                    if pipe.ttl(key) >= ttl_seconds:
                        return
                    pipe.multi()
                    pipe.set(key, "1", ex=ttl_seconds)
                    pipe.execute()
                    return
                except _redis.WatchError:  # type: ignore[union-attr]
                    continue

    def is_revoked(self, jti: str) -> bool:
        return self._redis.exists(self._key(jti)) == 1

    def _key(self, jti: str) -> str:
        return f"{self._key_prefix}{jti}"
