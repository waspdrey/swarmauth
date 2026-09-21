"""SwarmAuth: OAuth 2.1-style capability delegation for autonomous AI agent swarms."""

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import (
    AudienceMismatchError,
    CapabilityViolationError,
    ConstraintViolationError,
    InvalidSignatureError,
    MalformedTokenError,
    SwarmAuthError,
    TokenExpiredError,
    TokenNotYetValidError,
    TokenRevokedError,
    UnknownIssuerError,
)
from swarmauth.middleware import TokenIssuer, guard
from swarmauth.revocation import InMemoryRevocationStore, RevocationStore
from swarmauth.token import CapabilityClaims, CapabilityToken, Constraints, check_capability

__version__ = "0.1.6"

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
    "RevocationStore",
    "InMemoryRevocationStore",
    "__version__",
]
