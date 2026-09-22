import time

import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import TokenRevokedError
from swarmauth.middleware import guard, verify_and_check
from swarmauth.revocation import InMemoryRevocationStore
from swarmauth.token import CapabilityToken


def test_in_memory_store_reports_unrevoked_token_as_not_revoked():
    store = InMemoryRevocationStore()
    assert store.is_revoked("jti-1") is False


def test_in_memory_store_revokes_until_expiry():
    store = InMemoryRevocationStore()
    store.revoke("jti-1", expires_at=int(time.time()) + 60)
    assert store.is_revoked("jti-1") is True


def test_in_memory_store_treats_already_expired_revocation_as_a_no_op():
    store = InMemoryRevocationStore()
    store.revoke("jti-1", expires_at=int(time.time()) - 5)
    assert store.is_revoked("jti-1") is False


def test_in_memory_store_forgets_a_revocation_once_its_expiry_passes():
    store = InMemoryRevocationStore()
    store.revoke("jti-1", expires_at=int(time.time()) + 1)
    time.sleep(1.5)
    assert store.is_revoked("jti-1") is False


def test_in_memory_store_purges_every_expired_entry(monkeypatch):
    store = InMemoryRevocationStore()
    store.revoke("jti-1", expires_at=int(time.time()) + 30)
    store.revoke("jti-2", expires_at=int(time.time()) + 30)
    later = time.time() + 60
    monkeypatch.setattr("swarmauth.revocation.time.time", lambda: later)
    assert store.is_revoked("jti-1") is False
    assert store._revoked == {}


def test_verify_rejects_a_revoked_token():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])
    _, claims, _ = CapabilityToken.parse(token)

    store = InMemoryRevocationStore()
    store.revoke(claims.jti, expires_at=claims.exp)

    with pytest.raises(TokenRevokedError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, revocation_store=store)


def test_verify_accepts_a_token_whose_jti_was_never_revoked():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])

    store = InMemoryRevocationStore()
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, revocation_store=store)
    assert claims.capabilities == ["x"]


def test_verify_accepts_a_different_tokens_jti_even_when_one_is_revoked():
    kp = KeyPair.generate()
    revoked_token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])
    other_token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])
    _, revoked_claims, _ = CapabilityToken.parse(revoked_token)

    store = InMemoryRevocationStore()
    store.revoke(revoked_claims.jti, expires_at=revoked_claims.exp)

    CapabilityToken.verify(other_token, issuer_public_key=kp.public_bytes, revocation_store=store)


def test_verify_and_check_rejects_a_revoked_token():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="tool:b", capabilities=["tool:b"])
    _, claims, _ = CapabilityToken.parse(token)

    store = InMemoryRevocationStore()
    store.revoke(claims.jti, expires_at=claims.exp)

    with pytest.raises(TokenRevokedError):
        verify_and_check(
            token,
            issuer_public_key=kp.public_bytes,
            revocation_store=store,
            required_capability="tool:b",
        )


def test_guard_decorator_rejects_a_revoked_token_before_tool_execution():
    kp = KeyPair.generate()
    issuer_public_key = kp.public_bytes
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="tool:process_payout", capabilities=["tool:process_payout"])
    _, claims, _ = CapabilityToken.parse(token)

    store = InMemoryRevocationStore()
    store.revoke(claims.jti, expires_at=claims.exp)
    executed = False

    @guard("tool:process_payout", issuer_public_key=issuer_public_key, revocation_store=store)
    def process_payout(destination_account):
        nonlocal executed
        executed = True
        return "executed"

    with pytest.raises(TokenRevokedError):
        process_payout(destination_account="acct_1", token=token)
    assert executed is False


def test_guard_decorator_without_a_revocation_store_ignores_revocation():
    # revocation_store is opt-in; a verifier that never passes one behaves
    # exactly as before this feature existed.
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="tool:process_payout", capabilities=["tool:process_payout"])

    @guard("tool:process_payout", issuer_public_key=kp.public_bytes)
    def process_payout(destination_account):
        return "executed"

    assert process_payout(destination_account="acct_1", token=token) == "executed"


def test_verify_checks_revocation_only_after_signature_and_expiry():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"], ttl_seconds=1)
    time.sleep(3.5)

    store = InMemoryRevocationStore()
    from swarmauth.exceptions import TokenExpiredError

    with pytest.raises(TokenExpiredError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, revocation_store=store, leeway_seconds=1)
