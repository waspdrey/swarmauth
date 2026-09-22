"""Exception hierarchy for SwarmAuth.

``code`` is the stable, language-independent identifier from SPEC.md §7.
Class names are the reference Python SDK's mapping of those codes.
"""
from __future__ import annotations

from typing import Optional


class SwarmAuthError(Exception):
    """Base class for all SwarmAuth errors."""

    code: str = "SWARMAUTH_ERROR"


class MalformedTokenError(SwarmAuthError):
    """Raised when a token string cannot be parsed into a valid structure."""

    code = "MALFORMED_TOKEN"


class InvalidSignatureError(SwarmAuthError):
    """Raised when a token's Ed25519 signature does not verify against the issuer's public key."""

    code = "INVALID_SIGNATURE"


class TokenExpiredError(SwarmAuthError):
    """Raised when a token's `exp` claim is in the past, or `iat`/`exp` violate the max TTL."""

    code = "TOKEN_EXPIRED"


class TokenNotYetValidError(SwarmAuthError):
    """Raised when a token is presented before its `iat` claim."""

    code = "TOKEN_NOT_YET_VALID"


class TokenRevokedError(SwarmAuthError):
    """Raised when a token ID was revoked before its signed expiry."""

    code = "TOKEN_REVOKED"


class AudienceMismatchError(SwarmAuthError):
    """Raised when a token's `sub` claim does not match the agent/tool verifying it."""

    code = "AUDIENCE_MISMATCH"


class UnknownIssuerError(SwarmAuthError):
    """Raised when a KeyRegistry has no trusted key registered for a token's `iss`.

    Distinct from InvalidSignatureError: this means the verifier has no
    policy opinion about this issuer at all, not that a signature failed to
    verify against a known key.
    """

    code = "UNKNOWN_ISSUER"


class CapabilityViolationError(SwarmAuthError):
    """Raised when a token does not grant the capability required for the attempted action."""

    code = "CAPABILITY_VIOLATION"

    def __init__(self, message: str, *, required: Optional[str] = None, granted: Optional[list[str]] = None):
        super().__init__(message)
        self.required = required
        self.granted = granted or []


class ConstraintViolationError(SwarmAuthError):
    """Raised when an action would exceed a token's declared constraints
    (rate limit, execution cap, budget, or parameter allowlist)."""

    code = "CONSTRAINT_VIOLATION"

    def __init__(self, message: str, *, constraint: Optional[str] = None):
        super().__init__(message)
        self.constraint = constraint


class PolicyViolationError(SwarmAuthError):
    """Raised when an issuer is asked to sign a token outside its configured grant."""

    code = "POLICY_VIOLATION"


class DelegationError(SwarmAuthError):
    """Raised when a delegation chain widens authority or is presented incorrectly."""

    code = "DELEGATION_VIOLATION"
