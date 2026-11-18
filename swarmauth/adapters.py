"""Validated OAuth/WIMSE and Microsoft Entra claims adapters."""
from __future__ import annotations

import time
from typing import Any, Callable, Mapping, Optional, Sequence

from swarmauth.middleware import TokenIssuer
from swarmauth.token import Constraints

ClaimsValidator = Callable[[str], Mapping[str, Any]]


class OAuthDelegationAdapter:
    """Exchange an externally validated OAuth credential for a short-lived JCT.

    ``validate`` owns signature, issuer, audience, expiry, and revocation
    checks. This adapter only maps trusted claims into SwarmAuth.
    """

    def __init__(
        self,
        *,
        validate: ClaimsValidator,
        token_issuer: TokenIssuer,
        agent_claim: str = "client_id",
        subject_claim: str = "sub",
        scope_claim: str = "scope",
    ) -> None:
        self._validate = validate
        self._issuer = token_issuer
        self._agent_claim = agent_claim
        self._subject_claim = subject_claim
        self._scope_claim = scope_claim

    def exchange(
        self,
        credential: str,
        *,
        target: str,
        scope_to_capability: Mapping[str, str],
        constraints: Optional[Constraints] = None,
        ttl_seconds: int = 10,
    ) -> str:
        claims = self._validate(credential)
        agent_id = claims.get(self._agent_claim)
        sponsor = claims.get(self._subject_claim)
        if not isinstance(agent_id, str) or not agent_id or not isinstance(sponsor, str) or not sponsor:
            raise ValueError("validated OAuth claims do not identify both agent and sponsor")
        scopes = self._scopes(claims.get(self._scope_claim))
        capabilities = [scope_to_capability[scope] for scope in scopes if scope in scope_to_capability]
        if not capabilities:
            raise ValueError("validated OAuth credential grants no mapped SwarmAuth capability")
        remaining = self._remaining_ttl(claims)
        return self._issuer.issue(
            iss=agent_id,
            sub=target,
            capabilities=capabilities,
            constraints=constraints,
            ttl_seconds=min(ttl_seconds, remaining),
        )

    @staticmethod
    def _scopes(value: Any) -> Sequence[str]:
        if isinstance(value, str):
            return value.split()
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return value
        raise ValueError("validated OAuth scope claim is invalid")

    @staticmethod
    def _remaining_ttl(claims: Mapping[str, Any]) -> int:
        expires_at = claims.get("exp")
        if not isinstance(expires_at, int):
            raise ValueError("validated OAuth claims require integer exp")
        remaining = expires_at - int(time.time())
        if remaining < 1:
            raise ValueError("validated OAuth credential has expired")
        return remaining


class WIMSEClaimsAdapter(OAuthDelegationAdapter):
    """Preset for validated WIMSE workload/agent identity assertions."""

    def __init__(self, *, validate: ClaimsValidator, token_issuer: TokenIssuer) -> None:
        super().__init__(
            validate=validate,
            token_issuer=token_issuer,
            agent_claim="sub",
            subject_claim="sponsor",
            scope_claim="scope",
        )


class EntraAgentAdapter(OAuthDelegationAdapter):
    """Map validated Entra Agent ID/OBO claims without embedding Microsoft SDKs."""

    def __init__(self, *, validate: ClaimsValidator, token_issuer: TokenIssuer) -> None:
        super().__init__(
            validate=validate,
            token_issuer=token_issuer,
            agent_claim="azp",
            subject_claim="sub",
            scope_claim="scp",
        )
