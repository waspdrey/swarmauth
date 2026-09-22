"""Capability token creation, parsing, and verification.

A JSON Capability Token (JCT) is a compact, three-part string:

    base64url(header) . base64url(payload) . base64url(signature)

modeled on JWS/JWT but deliberately narrowed: the only algorithm is Ed25519
("EdDSA"), the only key format is a raw 32-byte public key, and the payload
schema is fixed to the claims below. See SPEC.md for the full specification.
"""
from __future__ import annotations

import json
import math
import time
from typing import Any, Optional, Sequence

from pydantic import BaseModel, Field, field_validator

from swarmauth.crypto import KeyPair, b64url_decode, b64url_encode, generate_jti, verify_signature
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
)
from swarmauth.registry import KeyRegistry
from swarmauth.revocation import RevocationStore

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

    iss: str = Field(..., description="Issuer agent ID, e.g. 'agent:requester-01'.")
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
    dlg: Optional[str] = Field(
        default=None,
        description="Agent id allowed to mint one narrower child token. A token with dlg set is not an execution credential.",
    )
    prf: Optional[str] = Field(
        default=None,
        description="Parent JCT this token attenuates. Present only on a single-hop delegated token.",
    )

    model_config = {"extra": "forbid"}

    @field_validator("capabilities")
    @classmethod
    def _capabilities_nonempty_strings(cls, v: list[str]) -> list[str]:
        if any(not isinstance(c, str) or not c for c in v):
            raise ValueError("capabilities must be a list of non-empty strings")
        return v

    @field_validator("dlg", "prf")
    @classmethod
    def _optional_nonempty(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and (not isinstance(v, str) or not v):
            raise ValueError("must be a non-empty string when present")
        return v


def claims_wire_dict(claims: CapabilityClaims) -> dict[str, Any]:
    """JSON object that is signed.

    Absent delegation claims are omitted. Encoding them as JSON null would
    change the canonical bytes of every existing token.
    """
    payload: dict[str, Any] = claims.model_dump(mode="json")
    if payload.get("dlg") is None:
        payload.pop("dlg", None)
    if payload.get("prf") is None:
        payload.pop("prf", None)
    return payload


def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Deterministic encoding used for both signing and verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def capability_covered(capability: str, granted: Sequence[str]) -> bool:
    """True when `capability` is equal to or narrower than some entry in `granted`."""
    for item in granted:
        if capability == item:
            return True
        if item.endswith(":*") and capability.startswith(item[:-1]):
            return True
    return False


def limit_is_wider(child: Optional[float], parent: Optional[float]) -> bool:
    """True when `child` allows more than `parent`.

    A parent limit of None means unlimited. A child limit of None is unlimited
    and therefore wider than any finite parent limit.
    """
    if parent is None:
        return False
    if child is None or not math.isfinite(child):
        return True
    return child > parent


def _require_ttl(ttl_seconds: int) -> None:
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValueError(f"ttl_seconds must be an integer from 1 to {MAX_TTL_SECONDS}")
    if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(f"ttl_seconds must be an integer from 1 to {MAX_TTL_SECONDS}")


def _sign(issuer_keypair: KeyPair, claims: CapabilityClaims) -> str:
    header = {"alg": ALG, "typ": TOKEN_TYPE, "kid": issuer_keypair.public_key_id}
    header_b64 = b64url_encode(_canonical_json(header))
    payload_b64 = b64url_encode(_canonical_json(claims_wire_dict(claims)))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = issuer_keypair.sign(signing_input)
    return f"{header_b64}.{payload_b64}.{b64url_encode(signature)}"


def _kid_bytes(header: dict[str, Any]) -> bytes:
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise MalformedTokenError("Token header is missing kid")
    try:
        raw = b64url_decode(kid)
    except (ValueError, UnicodeDecodeError) as exc:
        raise MalformedTokenError("Token kid is not valid base64url") from exc
    if len(raw) != 32:
        raise MalformedTokenError("Token kid is not a 32-byte Ed25519 public key")
    return raw


def _verify_kid_and_signature(
    header: dict[str, Any],
    claims: CapabilityClaims,
    signing_input: bytes,
    signature: bytes,
    *,
    issuer_public_key: Optional[bytes],
    key_registry: Optional[KeyRegistry],
    holder: bool = False,
) -> None:
    """Verify the signature against header.kid, and require that key to be trusted.

    The registry may hold several keys for one issuer during rotation. Only
    the key named by `kid` is tried. A signature that verifies under a
    different trusted key is still rejected.

    `holder=True` consults holder keys (delegation children) instead of root
    issuer keys. A holder key cannot authorize a token that has no parent.
    """
    kid = _kid_bytes(header)
    if key_registry is not None:
        trusted = key_registry.holder_keys_for(claims.iss) if holder else key_registry.keys_for(claims.iss)
        if not any(kid == key for key in trusted):
            raise InvalidSignatureError(f"Token kid is not a trusted key for issuer '{claims.iss}'")
        verify_signature(kid, signing_input, signature)
        return
    if holder:
        raise DelegationError("Delegated tokens require key_registry containing the root issuer and the delegate")
    if issuer_public_key is None:
        raise ValueError("Pass exactly one of issuer_public_key or key_registry")
    if kid != issuer_public_key:
        raise InvalidSignatureError("Token kid does not match the trusted issuer public key")
    verify_signature(issuer_public_key, signing_input, signature)


def _verify_core(
    token: str,
    *,
    issuer_public_key: Optional[bytes],
    key_registry: Optional[KeyRegistry],
    revocation_store: Optional[RevocationStore],
    leeway_seconds: int,
    holder: bool = False,
) -> CapabilityClaims:
    if (issuer_public_key is None) == (key_registry is None):
        raise ValueError("Pass exactly one of issuer_public_key or key_registry")

    header, claims, signing_input = CapabilityToken.parse(token)
    signature = b64url_decode(token.split(".")[2])
    _verify_kid_and_signature(
        header,
        claims,
        signing_input,
        signature,
        issuer_public_key=issuer_public_key,
        key_registry=key_registry,
        holder=holder,
    )

    if claims.exp - claims.iat > MAX_TTL_SECONDS:
        raise TokenExpiredError(f"Token TTL {claims.exp - claims.iat}s exceeds max {MAX_TTL_SECONDS}s")

    now = int(time.time())
    if now < claims.iat - leeway_seconds:
        raise TokenNotYetValidError(f"Token not valid until {claims.iat}, now is {now}")
    if now > claims.exp + leeway_seconds:
        raise TokenExpiredError(f"Token expired at {claims.exp}, now is {now}")

    if revocation_store is not None and revocation_store.is_revoked(claims.jti):
        raise TokenRevokedError(f"Token '{claims.jti}' has been revoked")
    return claims


def _assert_constraints_not_wider(parent: Constraints, child: Constraints) -> None:
    for name, parent_limit, child_limit in (
        ("max_calls", parent.max_calls, child.max_calls),
        ("max_amount_usd", parent.max_amount_usd, child.max_amount_usd),
        ("rate_limit_per_min", parent.rate_limit_per_min, child.rate_limit_per_min),
    ):
        if limit_is_wider(child_limit, parent_limit):
            raise DelegationError(f"Attenuated {name} widens the parent limit")
    for key, expected in parent.allowed_params.items():
        if child.allowed_params.get(key) != expected:
            raise DelegationError(f"Attenuated token drops or changes pinned parameter '{key}'")


def _assert_attenuated(parent: CapabilityClaims, child: CapabilityClaims) -> None:
    if parent.prf:
        raise DelegationError("Only one delegation hop is allowed")
    if not parent.dlg or parent.dlg != child.iss:
        raise DelegationError(f"Parent token does not authorize '{child.iss}' to attenuate it")
    if child.dlg:
        raise DelegationError("An attenuated token cannot itself be delegated further")
    if child.sub != parent.sub:
        raise DelegationError(f"Attenuated token retargets audience from '{parent.sub}' to '{child.sub}'")
    if child.iat < parent.iat or child.exp > parent.exp:
        raise DelegationError("Attenuated token lifetime is outside the parent token's lifetime")
    for capability in child.capabilities:
        if not capability_covered(capability, parent.capabilities):
            raise DelegationError(f"Attenuated capability '{capability}' exceeds the parent grant")
    _assert_constraints_not_wider(parent.constraints, child.constraints)


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
        dlg: Optional[str] = None,
    ) -> str:
        """Create and sign a new capability token.

        `ttl_seconds` must be an integer from 1 to MAX_TTL_SECONDS. A larger
        request is rejected so a caller cannot believe they minted a longer
        token than verifiers will accept.
        """
        _require_ttl(ttl_seconds)

        now = int(time.time())
        claims = CapabilityClaims(
            iss=iss,
            sub=sub,
            capabilities=capabilities,
            constraints=constraints or Constraints(),
            iat=now,
            exp=now + ttl_seconds,
            dlg=dlg,
        )
        return _sign(issuer_keypair, claims)

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
        issuer_public_key: Optional[bytes] = None,
        key_registry: Optional[KeyRegistry] = None,
        revocation_store: Optional[RevocationStore] = None,
        audience: Optional[str] = None,
        leeway_seconds: int = 2,
    ) -> CapabilityClaims:
        """Fully verify a token: signature, TTL ceiling, expiry, and (optionally) audience.

        Exactly one of `issuer_public_key` (trust a single, already-known key --
        the two-agent case) or `key_registry` (look up the trusted key(s) for
        `claims.iss`, supporting multiple issuers and key rotation) must be
        given.

        ``revocation_store``, when supplied, is checked after signature and
        lifetime validation so an incident-response system can immediately
        invalidate a specific token. Use a shared store for multi-process
        verifiers.

        Raises MalformedTokenError, InvalidSignatureError, UnknownIssuerError,
        TokenExpiredError, TokenNotYetValidError, TokenRevokedError,
        AudienceMismatchError, or DelegationError.
        """
        _preview_header, preview, _preview_input = CapabilityToken.parse(token)
        if preview.prf and key_registry is None:
            raise DelegationError(
                "Delegated tokens require key_registry containing the root issuer and the delegate"
            )

        claims = _verify_core(
            token,
            issuer_public_key=issuer_public_key,
            key_registry=key_registry,
            revocation_store=revocation_store,
            leeway_seconds=leeway_seconds,
            holder=preview.prf is not None,
        )

        if audience is not None and claims.sub != audience:
            raise AudienceMismatchError(f"Token audience '{claims.sub}' does not match '{audience}'")

        if claims.prf:
            _parent_header, parent_preview, _parent_input = CapabilityToken.parse(claims.prf)
            if parent_preview.prf:
                raise DelegationError("Only one delegation hop is allowed")
            parent = _verify_core(
                claims.prf,
                issuer_public_key=issuer_public_key,
                key_registry=key_registry,
                revocation_store=revocation_store,
                leeway_seconds=leeway_seconds,
            )
            _assert_attenuated(parent, claims)
        elif claims.dlg:
            raise DelegationError("A delegable token cannot be presented to a tool; attenuate it first")

        return claims

    @staticmethod
    def attenuate(
        *,
        issuer_keypair: KeyPair,
        parent: str,
        iss: str,
        capabilities: list[str],
        constraints: Optional[Constraints] = None,
        ttl_seconds: int = 60,
    ) -> str:
        """Mint one narrower token from `parent`.

        `sub` is copied from the parent. `iss` must equal the parent's `dlg`.
        The child cannot redelegate. The tool still verifies the parent
        signature; this method refuses to mint a child the attenuation rules
        would reject.
        """
        _require_ttl(ttl_seconds)
        _header, parent_claims, _signing_input = CapabilityToken.parse(parent)
        if parent_claims.exp - parent_claims.iat > MAX_TTL_SECONDS:
            raise TokenExpiredError(
                f"Parent TTL {parent_claims.exp - parent_claims.iat}s exceeds max {MAX_TTL_SECONDS}s"
            )
        now = int(time.time())
        if now < parent_claims.iat:
            raise TokenNotYetValidError(f"Parent token not valid until {parent_claims.iat}, now is {now}")
        if now > parent_claims.exp:
            raise TokenExpiredError(f"Parent token expired at {parent_claims.exp}, now is {now}")

        child_constraints = constraints or Constraints()
        exp = now + ttl_seconds
        child = CapabilityClaims(
            iss=iss,
            sub=parent_claims.sub,
            capabilities=capabilities,
            constraints=child_constraints,
            iat=now,
            exp=exp,
            prf=parent,
        )
        _assert_attenuated(parent_claims, child)
        return _sign(issuer_keypair, child)


def check_capability(claims: CapabilityClaims, required: str) -> None:
    """Raise CapabilityViolationError unless `required` is granted.

    Supports exact match or a `prefix:*` wildcard grant (e.g. `tool:*` grants
    `tool:read_invoice`).
    """
    if capability_covered(required, claims.capabilities):
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
