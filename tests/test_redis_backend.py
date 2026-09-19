"""Tests for RedisUsageTracker against a real Redis wire protocol.

By default these run against fakeredis's FakeStrictRedis (an in-process
emulator, not a mock of our own code) so they need no server or Docker
locally. Set SWARMAUTH_TEST_REDIS_URL (e.g. redis://localhost:6379/0) to run
the identical tests against an actual Redis server instead -- CI's
`redis-backend-live` job does exactly this against a real `redis:7`
container, since fakeredis's emulation, however faithful, isn't a substitute
for the genuine server.

Either way, this exercises the actual WATCH/MULTI/EXEC transaction behavior
described in swarmauth/backends/redis_backend.py, including retrying on a
genuine redis.WatchError.

Requires the optional `redis` extra: pip install -e ".[dev,redis]"
"""
from __future__ import annotations

import os

import pytest

fakeredis = pytest.importorskip("fakeredis", reason="pip install -e '.[dev,redis]' to run Redis backend tests")
redis = pytest.importorskip("redis", reason="pip install -e '.[dev,redis]' to run Redis backend tests")

from swarmauth.backends.redis_backend import RedisUsageTracker  # noqa: E402
from swarmauth.crypto import KeyPair  # noqa: E402
from swarmauth.exceptions import ConstraintViolationError  # noqa: E402
from swarmauth.token import CapabilityToken, Constraints  # noqa: E402

_LIVE_REDIS_URL = os.environ.get("SWARMAUTH_TEST_REDIS_URL")


def _second_client(fake_server):
    """A second, independent connection sharing the same backing store as
    `redis_client` -- a real second `redis.Redis` against the live server
    when SWARMAUTH_TEST_REDIS_URL is set, or a fakeredis client sharing the
    same in-process FakeServer otherwise.
    """
    if _LIVE_REDIS_URL:
        return redis.Redis.from_url(_LIVE_REDIS_URL)
    return fakeredis.FakeStrictRedis(server=fake_server)


@pytest.fixture()
def fake_server():
    return fakeredis.FakeServer()


@pytest.fixture()
def redis_client(fake_server):
    if _LIVE_REDIS_URL:
        client = redis.Redis.from_url(_LIVE_REDIS_URL)
        client.flushdb()
        yield client
        client.flushdb()
        return
    yield fakeredis.FakeStrictRedis(server=fake_server)


def _issue_and_parse(constraints: Constraints):
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:a", sub="tool:b", capabilities=["x"], constraints=constraints)
    _, claims, _ = CapabilityToken.parse(token)
    return claims


def test_max_calls_enforced_across_the_same_jti(redis_client):
    tracker = RedisUsageTracker(redis_client)
    claims = _issue_and_parse(Constraints(max_calls=2))

    tracker.check_and_record(claims)
    tracker.check_and_record(claims)
    with pytest.raises(ConstraintViolationError):
        tracker.check_and_record(claims)


def test_budget_enforced_and_no_partial_write_on_rejection(redis_client):
    tracker = RedisUsageTracker(redis_client)
    claims = _issue_and_parse(Constraints(max_amount_usd=50.0))

    tracker.check_and_record(claims, amount=30.0)
    with pytest.raises(ConstraintViolationError):
        tracker.check_and_record(claims, amount=30.0)  # would total 60 > 50

    # The rejected call must not have moved the spent amount at all.
    hash_key = f"swarmauth:usage:{claims.jti}"
    assert redis_client.hget(hash_key, "amount") == b"30"


def test_rate_limit_enforced(redis_client):
    tracker = RedisUsageTracker(redis_client)
    claims = _issue_and_parse(Constraints(rate_limit_per_min=2))

    tracker.check_and_record(claims)
    tracker.check_and_record(claims)
    with pytest.raises(ConstraintViolationError) as exc_info:
        tracker.check_and_record(claims)
    assert exc_info.value.constraint == "rate_limit_per_min"


def test_keys_get_a_ttl_matching_token_lifetime_ceiling(redis_client):
    tracker = RedisUsageTracker(redis_client)
    claims = _issue_and_parse(Constraints(max_calls=5))

    tracker.check_and_record(claims)

    hash_key = f"swarmauth:usage:{claims.jti}"
    zset_key = f"swarmauth:usage:{claims.jti}:calls"
    assert 0 < redis_client.ttl(hash_key) <= 330
    assert 0 < redis_client.ttl(zset_key) <= 330


def test_different_tokens_are_isolated_by_jti(redis_client):
    tracker = RedisUsageTracker(redis_client)
    claims_a = _issue_and_parse(Constraints(max_calls=1))
    claims_b = _issue_and_parse(Constraints(max_calls=1))
    assert claims_a.jti != claims_b.jti

    tracker.check_and_record(claims_a)
    # claims_b has its own independent budget despite identical constraints.
    tracker.check_and_record(claims_b)
    with pytest.raises(ConstraintViolationError):
        tracker.check_and_record(claims_a)


def test_retries_on_a_genuine_watch_error_and_then_succeeds(redis_client, fake_server, monkeypatch):
    """Simulates a real concurrent writer (a second verifier process touching
    the same jti between our WATCH and EXEC) by mutating the watched hash key
    through an independent client mid-check. This must produce a genuine
    redis.WatchError from the server's own MULTI/EXEC handling -- not a
    monkeypatched exception -- which the retry loop in check_and_record
    should absorb and recover from automatically.
    """
    tracker = RedisUsageTracker(redis_client)
    claims = _issue_and_parse(Constraints(max_calls=5))
    hash_key = f"swarmauth:usage:{claims.jti}"

    real_pipeline = redis_client.pipeline
    interference_done = {"done": False}

    def interfering_pipeline(*args, **kwargs):
        pipe = real_pipeline(*args, **kwargs)
        real_hget = pipe.hget

        def interfering_hget(*a, **k):
            if not interference_done["done"]:
                interference_done["done"] = True
                # A second, independent connection to the same backing store
                # writes to the watched key while our pipeline is mid-check
                # (after WATCH, before EXEC) -- a real concurrent verifier
                # process, not a fake exception.
                _second_client(fake_server).hincrby(hash_key, "calls", 1)
            return real_hget(*a, **k)

        pipe.hget = interfering_hget
        return pipe

    monkeypatch.setattr(redis_client, "pipeline", interfering_pipeline)

    tracker.check_and_record(claims)  # must retry internally after the real WatchError and succeed
    assert interference_done["done"]
    # 1 from the concurrent writer + 1 from our own successful retry.
    assert redis_client.hget(hash_key, "calls") == b"2"
