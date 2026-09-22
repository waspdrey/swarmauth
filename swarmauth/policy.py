"""Issuer policy: the signing key refuses grants it was not configured to make.

A private key that will sign any capability is not an authorization boundary.
`IssuerPolicy` is the boundary. It lives in the issuer process, next to the
private key, and `TokenIssuer` consults it before signing.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from swarmauth.exceptions import PolicyViolationError
from swarmauth.token import MAX_TTL_SECONDS, Constraints, capability_covered, limit_is_wider


@dataclass(frozen=True)
class Grant:
    """One allowed issuance: who may sign, for which audience, up to which ceiling."""

    iss: str
    sub: str
    capabilities: tuple[str, ...]
    max_ttl_seconds: int = MAX_TTL_SECONDS
    max_calls: Optional[int] = None
    max_amount_usd: Optional[float] = None
    rate_limit_per_min: Optional[int] = None
    delegates: tuple[str, ...] = ()
    pinned_params: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.iss or not self.sub:
            raise ValueError("Grant requires iss and sub")
        capabilities = tuple(self.capabilities)
        if not capabilities or any(not isinstance(item, str) or not item for item in capabilities):
            raise ValueError("Grant requires at least one non-empty capability")
        object.__setattr__(self, "capabilities", capabilities)
        if isinstance(self.max_ttl_seconds, bool) or not isinstance(self.max_ttl_seconds, int):
            raise ValueError(f"max_ttl_seconds must be an integer from 1 to {MAX_TTL_SECONDS}")
        if self.max_ttl_seconds <= 0 or self.max_ttl_seconds > MAX_TTL_SECONDS:
            raise ValueError(f"max_ttl_seconds must be an integer from 1 to {MAX_TTL_SECONDS}")
        if self.max_calls is not None and (isinstance(self.max_calls, bool) or self.max_calls < 1):
            raise ValueError("max_calls must be >= 1 when set")
        if self.max_amount_usd is not None and (
            isinstance(self.max_amount_usd, bool)
            or not isinstance(self.max_amount_usd, (int, float))
            or not math.isfinite(self.max_amount_usd)
            or self.max_amount_usd < 0
        ):
            raise ValueError("max_amount_usd must be a finite number >= 0 when set")
        if self.rate_limit_per_min is not None and (
            isinstance(self.rate_limit_per_min, bool) or self.rate_limit_per_min < 1
        ):
            raise ValueError("rate_limit_per_min must be >= 1 when set")
        delegates = tuple(self.delegates)
        if any(not isinstance(item, str) or not item for item in delegates):
            raise ValueError("delegates must be non-empty strings")
        object.__setattr__(self, "delegates", delegates)
        object.__setattr__(self, "pinned_params", dict(self.pinned_params))


class IssuerPolicy:
    """Set of grants a token issuer is allowed to sign."""

    def __init__(self, grants: Optional[Sequence[Grant]] = None) -> None:
        self._grants: list[Grant] = list(grants or [])

    def allow(self, grant: Grant) -> None:
        self._grants.append(grant)

    def check(
        self,
        *,
        iss: str,
        sub: str,
        capabilities: Sequence[str],
        constraints: Constraints,
        ttl_seconds: int,
        dlg: Optional[str] = None,
    ) -> None:
        """Raise PolicyViolationError unless one grant covers this issuance."""
        candidates = [grant for grant in self._grants if grant.iss == iss and grant.sub == sub]
        if not candidates:
            raise PolicyViolationError(f"No grant allows '{iss}' to issue tokens for '{sub}'")
        reasons: list[str] = []
        for grant in candidates:
            reason = _grant_denies(
                grant,
                capabilities=capabilities,
                constraints=constraints,
                ttl_seconds=ttl_seconds,
                dlg=dlg,
            )
            if reason is None:
                return
            reasons.append(reason)
        raise PolicyViolationError("; ".join(reasons))


def _grant_denies(
    grant: Grant,
    *,
    capabilities: Sequence[str],
    constraints: Constraints,
    ttl_seconds: int,
    dlg: Optional[str],
) -> Optional[str]:
    for capability in capabilities:
        if not capability_covered(capability, grant.capabilities):
            return f"Capability '{capability}' exceeds the grant for '{grant.iss}' -> '{grant.sub}'"
    if ttl_seconds > grant.max_ttl_seconds:
        return f"ttl_seconds {ttl_seconds} exceeds grant ceiling {grant.max_ttl_seconds}"
    if limit_is_wider(constraints.max_calls, grant.max_calls):
        return "max_calls exceeds the grant ceiling"
    if limit_is_wider(constraints.max_amount_usd, grant.max_amount_usd):
        return "max_amount_usd exceeds the grant ceiling"
    if limit_is_wider(constraints.rate_limit_per_min, grant.rate_limit_per_min):
        return "rate_limit_per_min exceeds the grant ceiling"
    for key, expected in grant.pinned_params.items():
        if constraints.allowed_params.get(key) != expected:
            return f"Issued token does not pin '{key}' to {expected!r}"
    if dlg is not None and dlg not in grant.delegates:
        return f"Grant does not allow delegation to '{dlg}'"
    return None
