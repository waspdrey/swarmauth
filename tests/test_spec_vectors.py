"""Verifies swarmauth's CURRENT implementation against spec/test-vectors/vectors.json.

This is the enforcement half of the interop story: the vectors file is the
artifact other (non-Python) implementations check themselves against; this
test makes sure swarmauth itself never silently drifts from what it
committed to. If a change to canonicalization, header shape, or the
verification algorithm breaks a committed vector, this test fails --
regenerate the vectors deliberately (`python
scripts/generate_test_vectors.py`) rather than let them go stale unnoticed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from swarmauth.crypto import KeyPair, b64url_encode
from swarmauth.exceptions import (
    AudienceMismatchError,
    CapabilityViolationError,
    ConstraintViolationError,
    DelegationError,
    InvalidSignatureError,
    MalformedTokenError,
    TokenExpiredError,
    TokenNotYetValidError,
    TokenRevokedError,
    UnknownIssuerError,
)
from swarmauth.registry import KeyRegistry
from swarmauth.token import ALG, TOKEN_TYPE, CapabilityClaims, CapabilityToken, _canonical_json, claims_wire_dict

VECTORS_PATH = Path(__file__).resolve().parent.parent / "spec" / "test-vectors" / "vectors.json"
VECTORS_DATA = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

ERROR_CODE_TO_EXCEPTION = {
    "MALFORMED_TOKEN": MalformedTokenError,
    "INVALID_SIGNATURE": InvalidSignatureError,
    "TOKEN_EXPIRED": TokenExpiredError,
    "TOKEN_NOT_YET_VALID": TokenNotYetValidError,
    "TOKEN_REVOKED": TokenRevokedError,
    "UNKNOWN_ISSUER": UnknownIssuerError,
    "AUDIENCE_MISMATCH": AudienceMismatchError,
    "CAPABILITY_VIOLATION": CapabilityViolationError,
    "CONSTRAINT_VIOLATION": ConstraintViolationError,
    "DELEGATION_VIOLATION": DelegationError,
}


@pytest.fixture(scope="module")
def issuer_keypair() -> KeyPair:
    return KeyPair.from_private_bytes(bytes.fromhex(VECTORS_DATA["issuer_private_key_seed_hex"]))


def test_vectors_file_has_expected_shape():
    assert VECTORS_DATA["vectors"], "vectors.json has no vectors -- did generation fail silently?"
    assert VECTORS_DATA["temporal_test_cases"], "vectors.json has no temporal_test_cases"
    assert len(VECTORS_DATA["issuer_private_key_seed_hex"]) == 64
    assert len(VECTORS_DATA["issuer_public_key_hex"]) == 64


def test_seed_derives_the_published_public_key(issuer_keypair):
    assert issuer_keypair.public_bytes.hex() == VECTORS_DATA["issuer_public_key_hex"]


@pytest.mark.parametrize("vector", VECTORS_DATA["vectors"], ids=lambda v: v["name"])
def test_vector(vector, issuer_keypair, monkeypatch):
    token = vector["token"]

    # A byte-exact vector needs a fixed iat/exp, which is inevitably outside
    # any real "now" once time has passed since generation. Pin the clock to
    # just after the vector's own iat so full verify() exercises the exact
    # scenario the vector was built to represent, not an incidental extra
    # "and also it happens to be expired by calendar time" failure.
    if "claims" in vector:
        monkeypatch.setattr("swarmauth.token.time.time", lambda: vector["claims"]["iat"] + 10)

    if vector["valid"]:
        claims = CapabilityToken.verify(token, **_trust(vector, issuer_keypair))
        assert claims.iss == vector["claims"]["iss"]
        assert claims.jti == vector["claims"]["jti"]
        assert claims.capabilities == vector["claims"]["capabilities"]
    else:
        expected_exc = ERROR_CODE_TO_EXCEPTION[vector["error_code"]]
        with pytest.raises(expected_exc) as caught:
            CapabilityToken.verify(token, **_trust(vector, issuer_keypair))
        assert caught.value.code == vector["error_code"]


def _trust(vector: dict, issuer_keypair: KeyPair) -> dict:
    if "delegate_public_key_hex" not in vector:
        return {"issuer_public_key": issuer_keypair.public_bytes}
    registry = KeyRegistry()
    registry.register(vector["root_iss"], issuer_keypair.public_bytes)
    registry.register_holder(vector["delegate_iss"], bytes.fromhex(vector["delegate_public_key_hex"]))
    return {"key_registry": registry}


def _build_token_with_exact_claims(keypair: KeyPair, *, iat: int, exp: int, jti: str) -> str:
    """Bypasses CapabilityToken.issue()'s MAX_TTL_SECONDS clamping and
    time.time()-derived iat -- needed to construct a token whose exp - iat
    deliberately exceeds the ceiling, for the ttl_ceiling_301_rejected case.
    """
    claims = CapabilityClaims(
        iss="agent:requester-01", sub="tool:x", capabilities=["tool:x"], iat=iat, exp=exp, jti=jti
    )
    header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": keypair.public_key_id}
    header_b64 = b64url_encode(_canonical_json(header))
    payload_b64 = b64url_encode(_canonical_json(claims_wire_dict(claims)))
    signature = keypair.sign(f"{header_b64}.{payload_b64}".encode("ascii"))
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


@pytest.mark.parametrize("case", VECTORS_DATA["temporal_test_cases"], ids=lambda c: c["name"])
def test_temporal_case(case, issuer_keypair, monkeypatch):
    token = _build_token_with_exact_claims(
        issuer_keypair, iat=case["iat"], exp=case["exp"], jti=f"temporal-{case['name']}"
    )
    monkeypatch.setattr("swarmauth.token.time.time", lambda: case["now"])

    if case["expect_valid"]:
        CapabilityToken.verify(
            token, issuer_public_key=issuer_keypair.public_bytes, leeway_seconds=case["leeway_seconds"]
        )
    else:
        expected_exc = ERROR_CODE_TO_EXCEPTION[case["error_code"]]
        with pytest.raises(expected_exc):
            CapabilityToken.verify(
                token, issuer_public_key=issuer_keypair.public_bytes, leeway_seconds=case["leeway_seconds"]
            )
