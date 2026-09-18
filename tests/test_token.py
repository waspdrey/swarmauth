import time

import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import (
    AudienceMismatchError,
    CapabilityViolationError,
    InvalidSignatureError,
    MalformedTokenError,
    TokenExpiredError,
)
from swarmauth.token import CapabilityToken, Constraints, check_capability


def test_issue_and_verify_roundtrip():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:a", sub="tool:b", caps=["tool:b"])
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, audience="tool:b")
    assert claims.iss == "agent:a"
    assert claims.sub == "tool:b"
    assert claims.caps == ["tool:b"]


def test_ttl_is_clamped_to_300s():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", caps=["x"], ttl_seconds=99999)
    _, claims, _ = CapabilityToken.parse(token)
    assert claims.exp - claims.iat == 300


def test_tampered_signature_rejected():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", caps=["x"])
    header, payload, sig = token.split(".")
    tampered = f"{header}.{payload}.{sig[:-4]}AAAA"
    with pytest.raises((InvalidSignatureError, MalformedTokenError)):
        CapabilityToken.verify(tampered, issuer_public_key=kp.public_bytes)


def test_wrong_issuer_key_rejected():
    kp = KeyPair.generate()
    other = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", caps=["x"])
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(token, issuer_public_key=other.public_bytes)


def test_expired_token_rejected():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", caps=["x"], ttl_seconds=1)
    time.sleep(3.5)
    with pytest.raises(TokenExpiredError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, leeway_seconds=1)


def test_audience_mismatch_rejected():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="tool:b", caps=["x"])
    with pytest.raises(AudienceMismatchError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, audience="tool:c")


def test_capability_exact_and_wildcard():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", caps=["tool:*"])
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes)
    check_capability(claims, "tool:read_invoice")  # should not raise

    token2 = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", caps=["tool:read_invoice"])
    claims2 = CapabilityToken.verify(token2, issuer_public_key=kp.public_bytes)
    with pytest.raises(CapabilityViolationError):
        check_capability(claims2, "tool:process_payout")


def test_malformed_token_rejected():
    kp = KeyPair.generate()
    with pytest.raises(MalformedTokenError):
        CapabilityToken.verify("not-a-token", issuer_public_key=kp.public_bytes)


def test_constraints_roundtrip():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(
        issuer_keypair=kp,
        iss="a",
        sub="b",
        caps=["x"],
        constraints=Constraints(max_calls=3, max_amount_usd=250.0, rate_limit_per_min=10),
    )
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes)
    assert claims.constraints.max_calls == 3
    assert claims.constraints.max_amount_usd == 250.0
    assert claims.constraints.rate_limit_per_min == 10
