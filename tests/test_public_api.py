"""Guards the top-level `swarmauth` package's public surface.

Every other test file imports from submodules directly (`swarmauth.token`,
`swarmauth.exceptions`, ...), which is convenient for testing but means
nothing exercises `swarmauth/__init__.py` itself -- exactly how
`UnknownIssuerError` (raised by CapabilityToken.verify/KeyRegistry, and
documented as such) went unexported from top-level `swarmauth` unnoticed:
every other exception in the same hierarchy was exported, this one wasn't,
and no test imported `from swarmauth import UnknownIssuerError` to catch it.
"""
import swarmauth
from swarmauth import exceptions


def test_all_names_in___all___are_actually_exported():
    for name in swarmauth.__all__:
        assert hasattr(swarmauth, name), f"{name!r} is in __all__ but not actually an attribute of swarmauth"


def test_every_swarmauth_error_is_exported_at_top_level():
    # Prevents a repeat of the UnknownIssuerError gap: any exception class
    # defined in swarmauth.exceptions must be importable as `swarmauth.X`,
    # not just `swarmauth.exceptions.X`.
    error_classes = [
        obj
        for obj in vars(exceptions).values()
        if isinstance(obj, type) and issubclass(obj, exceptions.SwarmAuthError)
    ]
    assert error_classes, "sanity check: expected to find at least SwarmAuthError itself"

    missing = [cls.__name__ for cls in error_classes if not hasattr(swarmauth, cls.__name__)]
    assert not missing, f"exception(s) defined in swarmauth.exceptions but not exported from swarmauth: {missing}"


def test_exception_codes_match_the_spec():
    expected = {
        "MalformedTokenError": "MALFORMED_TOKEN",
        "InvalidSignatureError": "INVALID_SIGNATURE",
        "TokenExpiredError": "TOKEN_EXPIRED",
        "TokenNotYetValidError": "TOKEN_NOT_YET_VALID",
        "TokenRevokedError": "TOKEN_REVOKED",
        "AudienceMismatchError": "AUDIENCE_MISMATCH",
        "UnknownIssuerError": "UNKNOWN_ISSUER",
        "CapabilityViolationError": "CAPABILITY_VIOLATION",
        "ConstraintViolationError": "CONSTRAINT_VIOLATION",
        "PolicyViolationError": "POLICY_VIOLATION",
        "DelegationError": "DELEGATION_VIOLATION",
    }
    for name, code in expected.items():
        assert getattr(exceptions, name).code == code
