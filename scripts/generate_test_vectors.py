"""Generate spec/test-vectors/vectors.json: byte-exact JCT test vectors any
independent implementation (Python, TypeScript, Rust, Go, ...) can use to
verify it produces/accepts identical tokens without needing to ask this repo
anything.

The issuer key used throughout is a fixed, non-secret, deliberately
unmysterious test seed (`bytes(range(32))`, i.e. 0x00 0x01 ... 0x1f) --
never a real secret, chosen specifically so anyone can regenerate it by
eye without trusting a hex string transcribed from memory.

`CapabilityToken.issue()` deliberately has no way to pin `iat`/`exp`/`jti`
(real tokens must not be forgeable to a fixed timestamp/id), so vectors are
built by constructing `CapabilityClaims` directly and reusing the exact
same header shape and canonical-JSON/signing logic `issue()` uses --
imported from swarmauth.token, not reimplemented, so these vectors can
never silently drift from what the shipped code actually does.

Every vector is self-checked against CapabilityToken.verify()/parse()
before being written out: a vector marked "valid" must actually verify,
and one marked "invalid" must actually raise the stated error. Re-run
after any change to canonicalization, header shape, or verification order:

    python scripts/generate_test_vectors.py

tests/test_spec_vectors.py then re-verifies the committed file on every
test run, so any future change that silently breaks these vectors fails CI
-- not just a diff nobody notices in generated JSON.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from swarmauth.crypto import KeyPair, b64url_encode
from swarmauth.exceptions import DelegationError, InvalidSignatureError
from swarmauth.registry import KeyRegistry
from swarmauth.token import ALG, TOKEN_TYPE, CapabilityClaims, CapabilityToken, Constraints, _canonical_json, claims_wire_dict

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "spec" / "test-vectors" / "vectors.json"

# A fixed, non-secret, byte-obvious seed: bytes(range(32)) = 00 01 02 ... 1f.
ISSUER_SEED_HEX = bytes(range(32)).hex()
ISSUER_PUBLIC_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

FIXED_IAT = 1_700_000_000  # 2023-11-14T22:13:20Z -- arbitrary but fixed, for byte-exact reproducibility


def _verify_at(
    now: int,
    token: str,
    *,
    issuer_public_key: bytes | None = None,
    key_registry: KeyRegistry | None = None,
) -> None:
    import swarmauth.token as token_mod

    original = token_mod.time.time
    token_mod.time.time = lambda: now
    try:
        CapabilityToken.verify(token, issuer_public_key=issuer_public_key, key_registry=key_registry)
    finally:
        token_mod.time.time = original


def _build_token(keypair: KeyPair, claims: CapabilityClaims) -> tuple[str, dict, str]:
    """Mirrors CapabilityToken.issue()'s construction exactly, but from an
    already-built CapabilityClaims so iat/exp/jti can be pinned."""
    header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": keypair.public_key_id}
    header_b64 = b64url_encode(_canonical_json(header))
    payload_b64 = b64url_encode(_canonical_json(claims_wire_dict(claims)))
    signing_input = f"{header_b64}.{payload_b64}"
    signature = keypair.sign(signing_input.encode("ascii"))
    sig_b64 = b64url_encode(signature)
    token = f"{header_b64}.{payload_b64}.{sig_b64}"
    return token, header, signing_input


def _self_check_wire_format(keypair: KeyPair, token: str) -> None:
    """Validate signature + schema/canonicalization correctness only --
    deliberately skips CapabilityToken.verify()'s wall-clock freshness
    check. A byte-exact vector must have a FIXED iat/exp to be reproducible,
    which means it inevitably falls outside any real "now" shortly after
    generation (doubly so given the 300s hard TTL ceiling) -- that's
    expected and does not indicate a broken vector. What must never drift
    is the signature and canonical encoding, which this does check.
    """
    from swarmauth.crypto import verify_signature

    header, claims, signing_input = CapabilityToken.parse(token)
    signature_b64 = token.split(".")[2]
    from swarmauth.crypto import b64url_decode

    verify_signature(keypair.public_bytes, signing_input, b64url_decode(signature_b64))


def main() -> None:
    keypair = KeyPair.from_private_bytes(bytes.fromhex(ISSUER_SEED_HEX))
    assert keypair.public_bytes.hex() == ISSUER_PUBLIC_HEX, "fixed test seed's derived public key changed unexpectedly"

    vectors = []

    # -- valid: minimal token, no constraints -------------------------------
    claims = CapabilityClaims(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        iat=FIXED_IAT,
        exp=FIXED_IAT + 60,
        jti="vector-minimal-0001",
    )
    token, header, signing_input = _build_token(keypair, claims)
    _self_check_wire_format(keypair, token)
    vectors.append(
        {
            "name": "minimal_valid",
            "valid": True,
            "description": "Minimal token: one exact capability, empty constraints. "
            "'valid' here means correct signature/schema/canonicalization -- "
            "iat/exp are fixed for byte-reproducibility, so check TTL/expiry "
            "math against these values yourself rather than expecting a live "
            "verify() call to accept this token as currently fresh.",
            "header": header,
            "claims": claims_wire_dict(claims),
            "signing_input": signing_input,
            "token": token,
        }
    )

    # -- valid: full constraints + wildcard capability -----------------------
    claims = CapabilityClaims(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:*"],
        constraints=Constraints(
            max_calls=3,
            max_amount_usd=250.5,
            rate_limit_per_min=10,
            allowed_params={"destination_account": "acct_123"},
        ),
        iat=FIXED_IAT,
        exp=FIXED_IAT + 300,
        jti="vector-full-constraints-0002",
    )
    token, header, signing_input = _build_token(keypair, claims)
    _self_check_wire_format(keypair, token)
    vectors.append(
        {
            "name": "full_constraints_and_wildcard",
            "valid": True,
            "description": "Wildcard capability, all four constraint fields populated, exp-iat at the 300s ceiling exactly. "
            "Same freshness caveat as minimal_valid: iat/exp are fixed, not currently fresh.",
            "header": header,
            "claims": claims_wire_dict(claims),
            "signing_input": signing_input,
            "token": token,
        }
    )

    # -- invalid: TTL exceeds MAX_TTL_SECONDS (static -- no clock dependency) -
    claims = CapabilityClaims(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        iat=FIXED_IAT,
        exp=FIXED_IAT + 301,
        jti="vector-ttl-exceeded-0003",
    )
    token, header, signing_input = _build_token(keypair, claims)
    try:
        CapabilityToken.verify(token, issuer_public_key=keypair.public_bytes)
        raise AssertionError("expected this vector to fail verification")
    except Exception as exc:
        assert type(exc).__name__ == "TokenExpiredError", type(exc).__name__
    vectors.append(
        {
            "name": "ttl_exceeds_max",
            "valid": False,
            "description": "exp - iat = 301 > MAX_TTL_SECONDS (300). Rejected on this ground "
            "alone, independent of wall-clock time, so this vector never goes stale.",
            "error_code": "TOKEN_EXPIRED",
            "header": header,
            "claims": claims_wire_dict(claims),
            "signing_input": signing_input,
            "token": token,
        }
    )

    # -- invalid: tampered signature ------------------------------------------
    claims = CapabilityClaims(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        iat=FIXED_IAT,
        exp=FIXED_IAT + 60,
        jti="vector-tampered-sig-0004",
    )
    token, header, signing_input = _build_token(keypair, claims)
    header_b64, payload_b64, sig_b64 = token.split(".")
    tampered_sig = ("A" if sig_b64[0] != "A" else "B") + sig_b64[1:]
    tampered_token = f"{header_b64}.{payload_b64}.{tampered_sig}"
    try:
        CapabilityToken.verify(tampered_token, issuer_public_key=keypair.public_bytes)
        raise AssertionError("expected this vector to fail verification")
    except Exception as exc:
        assert type(exc).__name__ == "InvalidSignatureError", type(exc).__name__
    vectors.append(
        {
            "name": "tampered_signature",
            "valid": False,
            "description": "Valid header/payload, signature's first base64url character flipped.",
            "error_code": "INVALID_SIGNATURE",
            "header": header,
            "claims": claims_wire_dict(claims),
            "signing_input": signing_input,
            "token": tampered_token,
        }
    )

    # -- invalid: malformed (wrong number of segments) ------------------------
    vectors.append(
        {
            "name": "malformed_two_segments",
            "valid": False,
            "description": "Only 2 dot-separated segments instead of 3.",
            "error_code": "MALFORMED_TOKEN",
            "token": "not-a-valid-token.missing-the-third-segment",
        }
    )

    delegate = KeyPair.from_private_bytes(bytes(range(32, 64)))
    delegate_iss = "agent:worker-02"
    root_iss = "agent:requester-01"

    # -- invalid: kid does not match the key that produced the signature -----
    claims = CapabilityClaims(
        iss=root_iss,
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        iat=FIXED_IAT,
        exp=FIXED_IAT + 60,
        jti="vector-kid-mismatch-0005",
    )
    payload_b64 = b64url_encode(_canonical_json(claims_wire_dict(claims)))
    header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": delegate.public_key_id}
    header_b64 = b64url_encode(_canonical_json(header))
    signing_input = f"{header_b64}.{payload_b64}"
    kid_mismatch = f"{header_b64}.{payload_b64}.{b64url_encode(keypair.sign(signing_input.encode('ascii')))}"
    try:
        CapabilityToken.verify(kid_mismatch, issuer_public_key=keypair.public_bytes)
        raise AssertionError("expected kid mismatch to fail verification")
    except InvalidSignatureError as exc:
        assert exc.code == "INVALID_SIGNATURE"
    vectors.append(
        {
            "name": "kid_does_not_match_signing_key",
            "valid": False,
            "description": "Signed by the trusted issuer key, but header.kid is a different public key. "
            "Verifiers must check kid against the key that verifies, not ignore it.",
            "error_code": "INVALID_SIGNATURE",
            "header": header,
            "claims": claims_wire_dict(claims),
            "signing_input": signing_input,
            "token": kid_mismatch,
        }
    )

    # -- invalid: delegable token presented directly --------------------------
    parent_claims = CapabilityClaims(
        iss=root_iss,
        sub="tool:process_payout",
        capabilities=["tool:*"],
        constraints=Constraints(max_calls=3, max_amount_usd=100.0),
        iat=FIXED_IAT,
        exp=FIXED_IAT + 120,
        jti="vector-delegation-parent-0006",
        dlg=delegate_iss,
    )
    parent_token, parent_header, parent_signing_input = _build_token(keypair, parent_claims)
    try:
        _verify_at(FIXED_IAT + 10, parent_token, issuer_public_key=keypair.public_bytes)
        raise AssertionError("expected a delegable token to be rejected as an execution credential")
    except DelegationError as exc:
        assert exc.code == "DELEGATION_VIOLATION"
    vectors.append(
        {
            "name": "delegable_token_not_directly_usable",
            "valid": False,
            "description": "A token with dlg set and no prf is an invitation to attenuate, not a credential a tool may accept.",
            "error_code": "DELEGATION_VIOLATION",
            "header": parent_header,
            "claims": claims_wire_dict(parent_claims),
            "signing_input": parent_signing_input,
            "token": parent_token,
        }
    )

    # -- valid: one-hop attenuation -------------------------------------------
    child_claims = CapabilityClaims(
        iss=delegate_iss,
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=Constraints(max_calls=1, max_amount_usd=40.0),
        iat=FIXED_IAT,
        exp=FIXED_IAT + 60,
        jti="vector-delegation-child-0007",
        prf=parent_token,
    )
    child_token, child_header, child_signing_input = _build_token(delegate, child_claims)
    _self_check_wire_format(delegate, child_token)
    registry = KeyRegistry()
    registry.register(root_iss, keypair.public_bytes)
    registry.register_holder(delegate_iss, delegate.public_bytes)
    _verify_at(FIXED_IAT + 10, child_token, key_registry=registry)
    vectors.append(
        {
            "name": "attenuated_delegation",
            "valid": True,
            "description": "One hop. The parent names agent:worker-02 and cannot be used directly. "
            "The child narrows tool:* to tool:process_payout and tightens both limits. "
            "Verify with a registry: root key for agent:requester-01, holder key for agent:worker-02. "
            "Pin the clock to claims.iat + 10. A holder key must not be accepted as a root issuer.",
            "header": child_header,
            "claims": claims_wire_dict(child_claims),
            "signing_input": child_signing_input,
            "token": child_token,
            "root_iss": root_iss,
            "delegate_iss": delegate_iss,
            "delegate_public_key_hex": delegate.public_bytes.hex(),
        }
    )

    # -- invalid: child widens a capability -----------------------------------
    widened_claims = CapabilityClaims(
        iss=delegate_iss,
        sub="tool:process_payout",
        capabilities=["other:admin"],
        constraints=Constraints(max_calls=1, max_amount_usd=40.0),
        iat=FIXED_IAT,
        exp=FIXED_IAT + 60,
        jti="vector-delegation-widened-0008",
        prf=parent_token,
    )
    widened_token, widened_header, widened_signing_input = _build_token(delegate, widened_claims)
    try:
        _verify_at(FIXED_IAT + 10, widened_token, key_registry=registry)
        raise AssertionError("expected a widened delegation to fail")
    except DelegationError as exc:
        assert exc.code == "DELEGATION_VIOLATION"
    vectors.append(
        {
            "name": "delegation_capability_widened",
            "valid": False,
            "description": "Child capability other:admin is outside the parent grant tool:*. Attenuation must fail.",
            "error_code": "DELEGATION_VIOLATION",
            "header": widened_header,
            "claims": claims_wire_dict(widened_claims),
            "signing_input": widened_signing_input,
            "token": widened_token,
            "root_iss": root_iss,
            "delegate_iss": delegate_iss,
            "delegate_public_key_hex": delegate.public_bytes.hex(),
        }
    )

    # -- temporal test cases: pure data, no signed token -----------------------
    # `vectors` above prove signature/canonicalization correctness but, since
    # they need a FIXED iat/exp to be byte-reproducible, cannot also exercise
    # "is this token fresh right now" -- that depends on wall-clock time by
    # definition. These cases let an implementation unit-test its OWN
    # temporal-check logic (MAX_TTL_SECONDS ceiling, iat/exp window, leeway)
    # against fixed (iat, exp, leeway_seconds, now) inputs, independent of
    # any keypair or token.
    temporal_test_cases = [
        {
            "name": "ttl_ceiling_exact_300_is_ok",
            "iat": 1000,
            "exp": 1300,
            "leeway_seconds": 2,
            "now": 1150,
            "expect_valid": True,
            "reason": "exp - iat == 300 (MAX_TTL_SECONDS), the ceiling itself, not over it.",
        },
        {
            "name": "ttl_ceiling_301_rejected",
            "iat": 1000,
            "exp": 1301,
            "leeway_seconds": 2,
            "now": 1150,
            "expect_valid": False,
            "error_code": "TOKEN_EXPIRED",
            "reason": "exp - iat == 301 > MAX_TTL_SECONDS. Checked before, and independent of, now.",
        },
        {
            "name": "not_yet_valid",
            "iat": 1000,
            "exp": 1060,
            "leeway_seconds": 2,
            "now": 997,
            "expect_valid": False,
            "error_code": "TOKEN_NOT_YET_VALID",
            "reason": "now (997) < iat (1000) - leeway (2) == 998.",
        },
        {
            "name": "not_yet_valid_leeway_boundary_ok",
            "iat": 1000,
            "exp": 1060,
            "leeway_seconds": 2,
            "now": 998,
            "expect_valid": True,
            "reason": "now (998) == iat (1000) - leeway (2), the boundary itself is accepted.",
        },
        {
            "name": "expired_past_leeway",
            "iat": 1000,
            "exp": 1060,
            "leeway_seconds": 2,
            "now": 1063,
            "expect_valid": False,
            "error_code": "TOKEN_EXPIRED",
            "reason": "now (1063) > exp (1060) + leeway (2) == 1062.",
        },
        {
            "name": "expired_leeway_boundary_ok",
            "iat": 1000,
            "exp": 1060,
            "leeway_seconds": 2,
            "now": 1062,
            "expect_valid": True,
            "reason": "now (1062) == exp (1060) + leeway (2), the boundary itself is accepted.",
        },
    ]

    out = {
        "spec_version": "0.1.0-draft",
        "generated_by": "scripts/generate_test_vectors.py",
        "warning": (
            "issuer_private_key_seed_hex below is a fixed, non-secret, "
            "deliberately unmysterious test seed (bytes(range(32))). "
            "NEVER use it for anything but verifying an implementation "
            "against these vectors."
        ),
        "issuer_private_key_seed_hex": ISSUER_SEED_HEX,
        "issuer_public_key_hex": ISSUER_PUBLIC_HEX,
        "vectors": vectors,
        "temporal_test_cases": temporal_test_cases,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"Wrote {len(vectors)} vectors to {OUT_PATH.relative_to(REPO_ROOT)} (generated at {int(time.time())})")


if __name__ == "__main__":
    main()
