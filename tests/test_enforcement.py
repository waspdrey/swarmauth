"""Regression coverage for execution-boundary failures found in the review."""
from __future__ import annotations

import asyncio
import dataclasses
import inspect
import os
from concurrent.futures import ThreadPoolExecutor

import fakeredis
import pytest
import redis

from swarmauth import CapabilityToken, Constraints, KeyPair, TokenIssuer, UsageTracker, guard, use_token
from swarmauth.backends.redis_backend import RedisUsageTracker
from swarmauth.exceptions import ConstraintViolationError, MalformedTokenError, TokenRevokedError
from swarmauth.middleware import verify_and_check
from swarmauth.registry import KeyRegistry
from swarmauth.revocation import InMemoryRevocationStore


@pytest.fixture(params=["memory", "redis"])
def tracker(request):
    if request.param == "memory":
        return UsageTracker()
    url = os.environ.get("SWARMAUTH_TEST_REDIS_URL")
    client = redis.Redis.from_url(url) if url else fakeredis.FakeStrictRedis()
    client.flushdb()
    yield_tracker = RedisUsageTracker(client)
    return yield_tracker


def chain(parent_limits, child_limits, count=3):
    root, worker = KeyPair.generate(), KeyPair.generate()
    registry = KeyRegistry()
    registry.register("root", root.public_bytes)
    registry.register_holder("worker", worker.public_bytes)
    parent = TokenIssuer(root).issue(
        iss="root", sub="tool:pay", capabilities=["tool:pay"], constraints=parent_limits, dlg="worker", ttl_seconds=30,
    )
    children = [TokenIssuer(worker).attenuate(
        parent, iss="worker", capabilities=["tool:pay"], constraints=child_limits, ttl_seconds=20,
    ) for _ in range(count)]
    return registry, parent, children


def call(token, registry, tracker, amount=0):
    return verify_and_check(token, key_registry=registry, audience="tool:pay", required_capability="tool:pay",
                            tracker=tracker, amount=amount)


@pytest.mark.parametrize("limits,amount", [
    (Constraints(max_calls=1), 0),
    (Constraints(max_amount_usd=100), 100),
    (Constraints(rate_limit_per_min=1), 0),
])
def test_siblings_share_every_parent_allowance(tracker, limits, amount):
    registry, _, children = chain(limits, limits)
    call(children[0], registry, tracker, amount)
    for child in children[1:]:
        with pytest.raises(ConstraintViolationError):
            call(child, registry, tracker, amount)


def test_child_rejection_does_not_consume_parent_allowance(tracker):
    registry, _, children = chain(Constraints(max_calls=2), Constraints(max_calls=1))
    call(children[0], registry, tracker)
    with pytest.raises(ConstraintViolationError):
        call(children[0], registry, tracker)
    call(children[1], registry, tracker)
    with pytest.raises(ConstraintViolationError):
        call(children[2], registry, tracker)


def test_concurrent_siblings_cannot_overspend_parent(tracker):
    registry, _, children = chain(Constraints(max_calls=2, max_amount_usd=100),
                                  Constraints(max_calls=1, max_amount_usd=50), count=12)
    def attempt(child):
        try:
            call(child, registry, tracker, 50)
            return True
        except ConstraintViolationError:
            return False
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert sum(pool.map(attempt, children)) == 2


def test_delegation_rejects_legacy_non_atomic_tracker():
    registry, _, children = chain(Constraints(max_calls=1), Constraints(max_calls=1))
    class LegacyTracker:
        def check_and_record(self, *args, **kwargs):
            pytest.fail("Non-atomic tracker must not be called")
    with pytest.raises(ConstraintViolationError, match="atomic"):
        call(children[0], registry, LegacyTracker())


def test_budgeted_tool_requires_explicit_amount_mapping():
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="root", sub="tool:pay", capabilities=["tool:pay"],
                                    constraints=Constraints(max_amount_usd=100))
    @guard("tool:pay", issuer_public_key=keys.public_bytes, tracker=UsageTracker())
    def pay(amount_usd):
        pytest.fail("Unmapped amount must never reach the tool")
    with pytest.raises(ConstraintViolationError, match="explicit amount"):
        pay(50000, token=token)


def test_explicit_zero_amount_is_valid():
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="root", sub="tool:pay", capabilities=["tool:pay"],
                                    constraints=Constraints(max_amount_usd=0))
    verify_and_check(token, issuer_public_key=keys.public_bytes, amount=0, tracker=UsageTracker())


@pytest.mark.parametrize("params", [None, {}, {"approved": 1}])
def test_pins_require_actual_parameters_and_exact_json_types(params):
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="root", sub="tool:pay", capabilities=["tool:pay"],
                                    constraints=Constraints(allowed_params={"approved": True}))
    with pytest.raises(ConstraintViolationError):
        verify_and_check(token, issuer_public_key=keys.public_bytes, params=params)


def test_null_pin_requires_presence_and_nested_pins_ignore_key_order():
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="root", sub="tool:pay", capabilities=["tool:pay"],
        constraints=Constraints(allowed_params={"optional": None, "order": {"id": 1, "approved": True}}))
    with pytest.raises(ConstraintViolationError):
        verify_and_check(token, issuer_public_key=keys.public_bytes, params={"order": {"id": 1, "approved": True}})
    verify_and_check(token, issuer_public_key=keys.public_bytes,
                     params={"optional": None, "order": {"approved": True, "id": 1}})


def test_revoked_token_never_returns_during_expiry_grace(monkeypatch):
    monkeypatch.setattr("time.time", lambda: 1000)
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="root", sub="tool:pay", capabilities=["tool:pay"], ttl_seconds=10)
    claims = CapabilityToken.parse(token)[1]
    store = InMemoryRevocationStore()
    store.revoke(claims.jti, expires_at=claims.exp)
    for now in (1010, 1011, 1012.99):
        monkeypatch.setattr("time.time", lambda now=now: now)
        with pytest.raises(TokenRevokedError):
            CapabilityToken.verify(token, issuer_public_key=keys.public_bytes, revocation_store=store)


@pytest.mark.parametrize("leeway", [-1, 3, 100, True, float("inf")])
def test_leeway_cannot_outlive_store_retention(leeway):
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="a", sub="b", capabilities=["x"])
    with pytest.raises(ValueError, match="leeway"):
        CapabilityToken.verify(token, issuer_public_key=keys.public_bytes, leeway_seconds=leeway)


def test_async_guard_preserves_coroutine_and_checks_when_awaited():
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="a", sub="tool:x", capabilities=["tool:x"])
    @guard("tool:x", issuer_public_key=keys.public_bytes)
    async def tool(value):
        return value
    assert inspect.iscoroutinefunction(tool)
    async def run():
        pending = tool(42)
        with use_token(token):
            assert await pending == 42
    asyncio.run(run())


def test_decision_events_include_metadata_without_tokens_or_arguments():
    keys = KeyPair.generate()
    token = TokenIssuer(keys).issue(iss="a", sub="tool:x", capabilities=["tool:x"], constraints=Constraints(max_calls=1))
    events = []
    @guard("tool:x", issuer_public_key=keys.public_bytes, tracker=UsageTracker(), on_decision=events.append)
    def tool(secret_argument):
        return "ok"
    assert tool("do-not-log", token=token) == "ok"
    with pytest.raises(ConstraintViolationError):
        tool("do-not-log", token=token)
    assert [event.decision for event in events] == ["allowed", "denied"]
    assert events[1].code == "CONSTRAINT_VIOLATION"
    assert events[0].issuer == "a"
    assert token not in repr([dataclasses.asdict(event) for event in events])
    assert "do-not-log" not in repr(events)


def test_malformed_header_is_a_protocol_error():
    from swarmauth.crypto import b64url_encode
    with pytest.raises(MalformedTokenError):
        CapabilityToken.parse(f"{b64url_encode(b'null')}.e30.AA")


def test_expiry_between_verification_and_reservation_cannot_reset_usage(tracker, monkeypatch):
    from swarmauth.exceptions import TokenExpiredError
    registry, _, children = chain(Constraints(max_calls=1), Constraints(max_calls=1))
    claims = CapabilityToken.verify(children[0], key_registry=registry)
    tracker.check_and_record(claims)
    monkeypatch.setattr("time.time", lambda: claims.exp + 3)
    with pytest.raises(TokenExpiredError):
        tracker.check_and_record(claims)
