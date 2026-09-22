"""SwarmAuth: OAuth 2.1-style capability delegation for autonomous AI agent swarms."""

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import (
    AudienceMismatchError,
    CapabilityViolationError,
    ConstraintViolationError,
    DelegationError,
    InvalidSignatureError,
    MalformedTokenError,
    PolicyViolationError,
    SwarmAuthError,
    TokenExpiredError,
    TokenNotYetValidError,
    TokenRevokedError,
    UnknownIssuerError,
)
from swarmauth.middleware import TokenIssuer, UsageTracker, guard, use_token
from swarmauth.policy import Grant, IssuerPolicy
from swarmauth.revocation import InMemoryRevocationStore, RevocationStore
from swarmauth.token import CapabilityClaims, CapabilityToken, Constraints, check_capability

__version__ = "0.1.7"

__all__ = [
    "KeyPair",
    "TokenIssuer",
    "guard",
    "CapabilityToken",
    "CapabilityClaims",
    "Constraints",
    "check_capability",
    "SwarmAuthError",
    "MalformedTokenError",
    "InvalidSignatureError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "TokenRevokedError",
    "UnknownIssuerError",
    "CapabilityViolationError",
    "ConstraintViolationError",
    "AudienceMismatchError",
    "PolicyViolationError",
    "DelegationError",
    "RevocationStore",
    "InMemoryRevocationStore",
    "UsageTracker",
    "use_token",
    "Grant",
    "IssuerPolicy",
    "__version__",
]
