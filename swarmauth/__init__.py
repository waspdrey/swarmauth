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
)
from swarmauth.token import CapabilityClaims, CapabilityToken, Constraints, check_capability

__version__ = "0.1.0"

__all__ = [
    "KeyPair",
    "CapabilityToken",
    "CapabilityClaims",
    "Constraints",
    "check_capability",
    "SwarmAuthError",
    "MalformedTokenError",
    "InvalidSignatureError",
    "TokenExpiredError",
    "TokenNotYetValidError",
    "CapabilityViolationError",
    "ConstraintViolationError",
    "AudienceMismatchError",
    "__version__",
]
