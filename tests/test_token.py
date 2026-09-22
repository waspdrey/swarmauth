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
    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:a", sub="tool:b", capabilities=["tool:b"])
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, audience="tool:b")
    assert claims.iss == "agent:a"
    assert claims.sub == "tool:b"
    assert claims.capabilities == ["tool:b"]


def test_ttl_above_300_is_rejected():
    kp = KeyPair.generate()
    with pytest.raises(ValueError, match="300"):
        CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"], ttl_seconds=301)
    with pytest.raises(ValueError, match="300"):
        CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"], ttl_seconds=0)
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"], ttl_seconds=300)
    _, claims, _ = CapabilityToken.parse(token)
    assert claims.exp - claims.iat == 300


def test_issued_token_omits_absent_delegation_claims():
    import json

    from swarmauth.crypto import b64url_decode

    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])
    payload = json.loads(b64url_decode(token.split(".")[1]))
    assert "dlg" not in payload
    assert "prf" not in payload


def test_kid_must_be_the_key_that_verifies():
    from swarmauth.crypto import b64url_encode
    from swarmauth.registry import KeyRegistry
    from swarmauth.token import ALG, TOKEN_TYPE, _canonical_json

    signer = KeyPair.generate()
    other = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=signer, iss="agent:a", sub="b", capabilities=["x"])
    _header_b64, payload_b64, _sig_b64 = token.split(".")
    header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": other.public_key_id}
    header_b64 = b64url_encode(_canonical_json(header))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    mismatched = f"{header_b64}.{payload_b64}.{b64url_encode(signer.sign(signing_input))}"

    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(mismatched, issuer_public_key=signer.public_bytes)

    registry = KeyRegistry()
    registry.register("agent:a", signer.public_bytes)
    registry.register("agent:a", other.public_bytes, rotate=True)
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(mismatched, key_registry=registry)

    # The original token, whose kid is the signing key, still verifies while both keys are trusted.
    assert CapabilityToken.verify(token, key_registry=registry).iss == "agent:a"


def test_tampered_signature_rejected():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])
    header, payload, sig = token.split(".")
    tampered = f"{header}.{payload}.{sig[:-4]}AAAA"
    with pytest.raises((InvalidSignatureError, MalformedTokenError)):
        CapabilityToken.verify(tampered, issuer_public_key=kp.public_bytes)


def test_wrong_issuer_key_rejected():
    kp = KeyPair.generate()
    other = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"])
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(token, issuer_public_key=other.public_bytes)


def test_expired_token_rejected():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["x"], ttl_seconds=1)
    time.sleep(3.5)
    with pytest.raises(TokenExpiredError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, leeway_seconds=1)


def test_audience_mismatch_rejected():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="tool:b", capabilities=["x"])
    with pytest.raises(AudienceMismatchError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, audience="tool:c")


def test_capability_exact_and_wildcard():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["tool:*"])
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes)
    check_capability(claims, "tool:read_invoice")  # should not raise

    token2 = CapabilityToken.issue(issuer_keypair=kp, iss="a", sub="b", capabilities=["tool:read_invoice"])
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
        capabilities=["x"],
        constraints=Constraints(max_calls=3, max_amount_usd=250.0, rate_limit_per_min=10),
    )
    claims = CapabilityToken.verify(token, issuer_public_key=kp.public_bytes)
    assert claims.constraints.max_calls == 3
    assert claims.constraints.max_amount_usd == 250.0
    assert claims.constraints.rate_limit_per_min == 10
