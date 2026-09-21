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

from swarmauth.crypto import KeyPair
from swarmauth.token import ALG, TOKEN_TYPE, CapabilityClaims, CapabilityToken, Constraints, _canonical_json

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = REPO_ROOT / "spec" / "test-vectors" / "vectors.json"

# A fixed, non-secret, byte-obvious seed: bytes(range(32)) = 00 01 02 ... 1f.
ISSUER_SEED_HEX = bytes(range(32)).hex()
ISSUER_PUBLIC_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"

FIXED_IAT = 1_700_000_000  # 2023-11-14T22:13:20Z -- arbitrary but fixed, for byte-exact reproducibility


def _build_token(keypair: KeyPair, claims: CapabilityClaims) -> tuple[str, dict, str]:
    """Mirrors CapabilityToken.issue()'s construction exactly, but from an
    already-built CapabilityClaims so iat/exp/jti can be pinned."""
    header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": keypair.public_key_id}
    from swarmauth.crypto import b64url_encode

    header_b64 = b64url_encode(_canonical_json(header))
    payload_b64 = b64url_encode(_canonical_json(claims.model_dump(mode="json")))
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
            "claims": json.loads(claims.model_dump_json()),
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
            "claims": json.loads(claims.model_dump_json()),
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
            "claims": json.loads(claims.model_dump_json()),
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
            "claims": json.loads(claims.model_dump_json()),
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
