"""Atomic token accounting and shared, currency-aware task/agent budgets.

Budgets are trusted verifier configuration. Tokens bind budget_id, currency,
and amount_minor through existing allowed_params; normal parameter checking
binds these signed values to the actual tool call. The explicit shared_budget
constraint makes unsupported execution boundaries fail closed.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, NoReturn, Optional, Sequence

from swarmauth.exceptions import ConstraintViolationError, TokenExpiredError
from swarmauth.limits import RETENTION_AFTER_EXP_SECONDS
from swarmauth.middleware import _decimal_sum, _decimal_text, _validated_amount
from swarmauth.token import CapabilityClaims


def _deny(message: str) -> NoReturn:
    raise ConstraintViolationError(message, constraint="shared_budget")


@dataclass(frozen=True)
class BudgetRule:
    id: str
    issuers: tuple[str, ...]
    currency: str
    max_amount_minor: int
    expires_at: int
    max_calls: Optional[int] = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id:
            raise ValueError("Budget id must be a non-empty string")
        if not self.issuers or any(not isinstance(issuer, str) or not issuer for issuer in self.issuers):
            raise ValueError("Budget requires trusted issuers")
        object.__setattr__(self, "issuers", tuple(self.issuers))
        if not isinstance(self.currency, str) or not re.fullmatch(r"[A-Z]{3}", self.currency):
            raise ValueError("currency must be an uppercase three-letter code")
        if type(self.max_amount_minor) is not int or not 0 <= self.max_amount_minor <= 2**53 - 1:
            raise ValueError("max_amount_minor must be a non-negative safe integer")
        if type(self.expires_at) is not int or not 0 < self.expires_at <= 2**53 - 1:
            raise ValueError("expires_at must be a positive safe integer")
        if self.max_calls is not None and (type(self.max_calls) is not int or not 1 <= self.max_calls <= 2**53 - 1):
            raise ValueError("max_calls must be a positive safe integer")


@dataclass
class _Record:
    key: str
    expiry: float
    calls: Optional[int] = None
    usd: Optional[float] = None
    rate: Optional[int] = None
    minor_limit: Optional[int] = None
    minor: int = 0


class BudgetUsageTracker:
    """Single-process ledger. Fresh tokens share a named budget's allowance.

    Token and budget counters are reserved together. Use RedisBudgetUsageTracker
    when more than one process can accept a token. Scope expiry is independent
    of the 30-second token ceiling and must be identical on every verifier.
    """

    requires_chain = True
    supports_shared_budgets = True

    def __init__(self, rules: Sequence[BudgetRule], *, require_budget: bool = True) -> None:
        self.rules = {rule.id: rule for rule in rules}
        if len(self.rules) != len(rules):
            raise ValueError("Budget ids must be unique")
        self.require_budget = require_budget
        self._entries: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _records(self, chain: Sequence[CapabilityClaims], now: float) -> list[_Record]:
        if not chain or len({claims.jti for claims in chain}) != len(chain):
            _deny("Delegation token ids must be distinct")
        records = []
        for claims in chain:
            expiry = claims.exp + RETENTION_AFTER_EXP_SECONDS
            if now >= expiry:
                raise TokenExpiredError("Token expired before usage reservation")
            limits = claims.constraints
            records.append(_Record(
                json.dumps(["token", claims.jti], ensure_ascii=False, separators=(",", ":")), expiry,
                limits.max_calls, limits.max_amount_usd, limits.rate_limit_per_min,
            ))
        pins = chain[-1].constraints.allowed_params
        budget_id = chain[-1].constraints.shared_budget
        if budget_id is None and not self.require_budget:
            return records
        if not isinstance(budget_id, str) or budget_id not in self.rules:
            _deny("Token must pin a configured budget_id")
        rule = self.rules[budget_id]
        if chain[0].iss not in rule.issuers:
            _deny("Issuer cannot charge this budget")
        if now >= rule.expires_at:
            _deny("Shared budget expired")
        minor = pins.get("amount_minor")
        if isinstance(minor, bool) or not isinstance(minor, (int, float)) or not 0 <= minor <= 2**53 - 1 or int(minor) != minor:
            _deny("Token must pin a non-negative safe integer amount_minor")
        minor = int(minor)
        if pins.get("currency") != rule.currency:
            _deny("Token currency does not match shared budget")
        records.append(_Record(
            json.dumps(["budget", rule.id], ensure_ascii=False, separators=(",", ":")), rule.expires_at, calls=rule.max_calls,
            minor_limit=rule.max_amount_minor, minor=minor,
        ))
        return records

    @staticmethod
    def _pending(record: _Record, current: dict[str, Any], now: float, amount: float) -> dict[str, Any]:
        calls = int(current.get("calls", 0)) + 1
        total = _decimal_sum(Decimal(str(current.get("usd", "0"))), amount)
        minor = int(current.get("minor", 0)) + record.minor
        recent = [stamp for stamp in current.get("timestamps", []) if stamp >= now - 60]
        if record.calls is not None and calls > record.calls:
            _deny("Call allowance exhausted")
        if record.usd is not None and total > Decimal(str(record.usd)):
            _deny("Token USD allowance exhausted")
        if record.rate is not None and len(recent) + 1 > record.rate:
            _deny("Token rate allowance exhausted")
        if record.minor_limit is not None and minor > record.minor_limit:
            _deny("Shared currency budget exhausted")
        return {"calls": calls, "usd": _decimal_text(total), "minor": minor,
                "timestamps": [*recent, now] if record.rate is not None else [], "expiry": record.expiry}

    def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        self.check_and_record_chain([claims], amount=amount)

    def check_and_record_chain(self, chain: Sequence[CapabilityClaims], *, amount: float = 0.0) -> None:
        amount = _validated_amount(amount)
        with self._lock:
            now = time.time()
            records = self._records(chain, now)
            pending = {record.key: self._pending(record, self._entries.get(record.key, {}), now, amount)
                       for record in records}
            self._entries = {key: entry for key, entry in self._entries.items() if entry["expiry"] > now}
            self._entries.update(pending)


class RedisBudgetUsageTracker(BudgetUsageTracker):
    """Durable shared ledger. WATCH all token/scope keys, commit all or none.

    The prefix must be shared by all verifier processes for these budgets.
    Use a dedicated Redis database configured without eviction and with the
    durability guarantees your application needs. Redis Cluster is unsupported.
    """

    def __init__(
        self, client: Any, rules: Sequence[BudgetRule], *, key_prefix: str = "swarmauth:ledger:",
        require_budget: bool = True, max_retries: int = 64,
    ) -> None:
        super().__init__(rules, require_budget=require_budget)
        if type(max_retries) is not int or max_retries < 1:
            raise ValueError("max_retries must be positive")
        self.client, self.key_prefix, self.max_retries = client, key_prefix, max_retries

    def check_and_record_chain(self, chain: Sequence[CapabilityClaims], *, amount: float = 0.0) -> None:
        import redis

        amount = _validated_amount(amount)
        with self.client.pipeline() as pipe:
            for _ in range(self.max_retries):
                try:
                    now = time.time()
                    records = self._records(chain, now)
                    keys = [self.key_prefix + hashlib.sha256(record.key.encode()).hexdigest() for record in records]
                    pipe.watch(*keys)
                    current = [json.loads(pipe.get(key) or "{}") for key in keys]
                    # Recheck expiry after network reads and before committing.
                    now = time.time()
                    records = self._records(chain, now)
                    pending = [self._pending(record, entry, now, amount)
                               for record, entry in zip(records, current, strict=True)]
                    pipe.multi()
                    for key, record, entry in zip(keys, records, pending, strict=True):
                        ttl = max(1, math.ceil((record.expiry - now) * 1000))
                        pipe.set(key, json.dumps(entry, separators=(",", ":")), px=ttl)
                    pipe.execute()
                    return
                except redis.WatchError:
                    continue
        _deny("Shared budget contention exceeded retry limit")


class AsyncUsageTracker:
    """Await a synchronous Redis/in-memory backend without blocking the loop.

    Cancellation can occur after a reservation commits; allowances remain
    consumed in that case. Retrying side effects requires application idempotency.
    """

    def __init__(self, tracker: Any) -> None:
        self.tracker = tracker
        self.requires_chain = bool(getattr(tracker, "requires_chain", False))
        self.supports_shared_budgets = bool(getattr(tracker, "supports_shared_budgets", False))

    async def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        import asyncio
        await asyncio.to_thread(self.tracker.check_and_record, claims, amount=amount)

    async def check_and_record_chain(self, chain: Sequence[CapabilityClaims], *, amount: float = 0.0) -> None:
        import asyncio
        method = getattr(self.tracker, "check_and_record_chain", None)
        if not callable(method):
            _deny("Delegated limits require atomic chain accounting")
        await asyncio.to_thread(method, chain, amount=amount)
