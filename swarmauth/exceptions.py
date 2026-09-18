"""Exception hierarchy for SwarmAuth."""
from __future__ import annotations

from typing import Optional


class SwarmAuthError(Exception):
    """Base class for all SwarmAuth errors."""


class MalformedTokenError(SwarmAuthError):
    """Raised when a token string cannot be parsed into a valid structure."""


class InvalidSignatureError(SwarmAuthError):
    """Raised when a token's Ed25519 signature does not verify against the issuer's public key."""


class TokenExpiredError(SwarmAuthError):
    """Raised when a token's `exp` claim is in the past, or `iat`/`exp` violate the max TTL."""


class TokenNotYetValidError(SwarmAuthError):
    """Raised when a token is presented before its `iat` claim."""


class AudienceMismatchError(SwarmAuthError):
    """Raised when a token's `sub` claim does not match the agent/tool verifying it."""


class CapabilityViolationError(SwarmAuthError):
    """Raised when a token does not grant the capability required for the attempted action."""

    def __init__(self, message: str, *, required: Optional[str] = None, granted: Optional[list] = None):
        super().__init__(message)
        self.required = required
        self.granted = granted or []


class ConstraintViolationError(SwarmAuthError):
    """Raised when an action would exceed a token's declared constraints
    (rate limit, execution cap, budget, or parameter allowlist)."""

    def __init__(self, message: str, *, constraint: Optional[str] = None):
        super().__init__(message)
        self.constraint = constraint
