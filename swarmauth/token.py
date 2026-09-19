"""Capability token creation, parsing, and verification.

A JSON Capability Token (JCT) is a compact, three-part string:

    base64url(header) . base64url(payload) . base64url(signature)

modeled on JWS/JWT but deliberately narrowed: the only algorithm is Ed25519
("EdDSA"), the only key format is a raw 32-byte public key, and the payload
schema is fixed to the claims below. See SPEC.md for the full specification.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

from swarmauth.crypto import KeyPair, b64url_decode, b64url_encode, generate_jti, verify_signature
from swarmauth.exceptions import (
    AudienceMismatchError,
    MalformedTokenError,
    TokenExpiredError,
    TokenNotYetValidError,
)
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError

TOKEN_TYPE = "JCT"  # JSON Capability Token
ALG = "EdDSA"
MAX_TTL_SECONDS = 300  # hard ceiling; enforced independent of caller input


class Constraints(BaseModel):
    """Optional runtime limits scoped to a single token."""

    max_calls: Optional[int] = Field(
        default=None, ge=1, description="Max number of times this token may authorize an action."
    )
    max_amount_usd: Optional[float] = Field(
        default=None, ge=0, description="Max cumulative monetary amount this token may authorize."
    )
    rate_limit_per_min: Optional[int] = Field(
        default=None, ge=1, description="Max invocations per 60s sliding window."
    )
    allowed_params: dict[str, Any] = Field(
        default_factory=dict,
        description="Exact-match allowlist for specific call parameters, "
        "e.g. {'destination_account': 'acct_123'}.",
    )

    model_config = {"extra": "forbid"}


class CapabilityClaims(BaseModel):
    """The signed payload of a Capability Token."""

    iss: str = Field(..., description="Issuer agent ID, e.g. 'agent:sales-agent-01'.")
    sub: str = Field(
        ..., description="Target agent/tool ID this token authorizes calling into, e.g. 'tool:process_payout'."
    )
    capabilities: list[str] = Field(
        ..., min_length=1, description="Capabilities granted, e.g. ['tool:read_invoice']."
    )
    constraints: Constraints = Field(default_factory=Constraints)
    iat: int = Field(..., description="Issued-at, unix seconds.")
    exp: int = Field(..., description="Expiry, unix seconds. Must satisfy exp - iat <= 300.")
    jti: str = Field(default_factory=generate_jti, description="Unique token ID, for usage/replay tracking.")

    model_config = {"extra": "forbid"}

    @field_validator("capabilities")
    @classmethod
    def _capabilities_nonempty_strings(cls, v: list[str]) -> list[str]:
        if any(not isinstance(c, str) or not c for c in v):
            raise ValueError("capabilities must be a list of non-empty strings")
        return v


def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Deterministic encoding used for both signing and verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class CapabilityToken:
    """Facade for issuing and verifying JCT strings."""

    @staticmethod
    def issue(
        *,
        issuer_keypair: KeyPair,
        iss: str,
        sub: str,
        capabilities: list[str],
        constraints: Optional[Constraints] = None,
        ttl_seconds: int = 60,
    ) -> str:
        """Create and sign a new capability token. `ttl_seconds` is clamped to MAX_TTL_SECONDS."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        ttl_seconds = min(ttl_seconds, MAX_TTL_SECONDS)

        now = int(time.time())
        claims = CapabilityClaims(
            iss=iss,
            sub=sub,
            capabilities=capabilities,
            constraints=constraints or Constraints(),
            iat=now,
            exp=now + ttl_seconds,
        )

        header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": issuer_keypair.public_key_id}
        header_b64 = b64url_encode(_canonical_json(header))
        payload_b64 = b64url_encode(_canonical_json(claims.model_dump(mode="json")))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        signature = issuer_keypair.sign(signing_input)
        sig_b64 = b64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    @staticmethod
    def parse(token: str) -> tuple[dict[str, Any], CapabilityClaims, bytes]:
        """Decode a token WITHOUT verifying its signature. Returns (header, claims, signing_input)."""
        parts = token.split(".")
        if len(parts) != 3:
            raise MalformedTokenError(f"Expected 3 dot-separated parts, got {len(parts)}")
        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(b64url_decode(header_b64))
            payload = json.loads(b64url_decode(payload_b64))
        except (ValueError, UnicodeDecodeError) as exc:
            raise MalformedTokenError("Token header/payload is not valid base64url JSON") from exc

        if header.get("typ") != TOKEN_TYPE or header.get("alg") != ALG:
            raise MalformedTokenError(f"Unsupported token header: {header}")

        try:
            claims = CapabilityClaims.model_validate(payload)
        except Exception as exc:  # pydantic.ValidationError
            raise MalformedTokenError(f"Invalid claims schema: {exc}") from exc

        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return header, claims, signing_input

    @staticmethod
    def verify(
        token: str,
        *,
        issuer_public_key: bytes,
        audience: Optional[str] = None,
        leeway_seconds: int = 2,
    ) -> CapabilityClaims:
        """Fully verify a token: signature, TTL ceiling, expiry, and (optionally) audience.

        Raises MalformedTokenError, InvalidSignatureError, TokenExpiredError,
        TokenNotYetValidError, or AudienceMismatchError.
        """
        header, claims, signing_input = CapabilityToken.parse(token)
        signature = b64url_decode(token.split(".")[2])

        verify_signature(issuer_public_key, signing_input, signature)

        if claims.exp - claims.iat > MAX_TTL_SECONDS:
            raise TokenExpiredError(f"Token TTL {claims.exp - claims.iat}s exceeds max {MAX_TTL_SECONDS}s")

        now = int(time.time())
        if now < claims.iat - leeway_seconds:
            raise TokenNotYetValidError(f"Token not valid until {claims.iat}, now is {now}")
        if now > claims.exp + leeway_seconds:
            raise TokenExpiredError(f"Token expired at {claims.exp}, now is {now}")

        if audience is not None and claims.sub != audience:
            raise AudienceMismatchError(f"Token audience '{claims.sub}' does not match '{audience}'")

        return claims


def check_capability(claims: CapabilityClaims, required: str) -> None:
    """Raise CapabilityViolationError unless `required` is granted.

    Supports exact match or a `prefix:*` wildcard grant (e.g. `tool:*` grants
    `tool:read_invoice`).
    """
    for granted in claims.capabilities:
        if granted == required:
            return
        if granted.endswith(":*") and required.startswith(granted[:-1]):
            return
    raise CapabilityViolationError(
        f"Token does not grant capability '{required}'", required=required, granted=claims.capabilities
    )


def check_params(claims: CapabilityClaims, params: dict[str, Any]) -> None:
    """Enforce the constraints.allowed_params exact-match allowlist, if present."""
    allowed = claims.constraints.allowed_params
    for key, expected in allowed.items():
        if params.get(key) != expected:
            raise ConstraintViolationError(
                f"Parameter '{key}'={params.get(key)!r} does not match required value {expected!r}",
                constraint="allowed_params",
            )
