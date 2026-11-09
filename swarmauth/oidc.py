"""Optional OIDC resource-server principal resolver for the control plane."""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Mapping, Sequence, cast
from urllib.request import Request, urlopen

from swarmauth.control_plane import Principal
from swarmauth.exceptions import ControlPlaneAuthenticationError
from swarmauth.middleware import bearer_token_from_headers


class OIDCPrincipalResolver:
    """Validate signed OIDC access tokens and produce tenant-scoped principals.

    Install the optional dependency with ``pip install swarmauth[oidc]``.
    JWKS is fetched from the configured URL and cached briefly. The resolver
    never returns token contents or stores bearer credentials.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        jwks_url: str,
        tenant_claim: str = "tenant_id",
        roles_claim: str = "roles",
        algorithms: Sequence[str] = ("RS256",),
        jwks_ttl_seconds: int = 300,
    ) -> None:
        if not issuer or not audience or not jwks_url or jwks_ttl_seconds <= 0:
            raise ValueError("issuer, audience, jwks_url, and positive jwks_ttl_seconds are required")
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self.tenant_claim = tenant_claim
        self.roles_claim = roles_claim
        self.algorithms = tuple(algorithms)
        self.jwks_ttl_seconds = jwks_ttl_seconds
        self._jwks: dict[str, Any] | None = None
        self._jwks_expires_at = 0.0
        self._lock = threading.Lock()

    def __call__(self, headers: Mapping[str, str]) -> Principal:
        try:
            import jwt

            token = bearer_token_from_headers(headers)
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            algorithm = header.get("alg")
            if not isinstance(kid, str) or algorithm not in self.algorithms:
                raise ValueError("untrusted JWT header")
            jwk = self._key(kid)
            claims = jwt.decode(
                token,
                key=jwt.PyJWK(jwk).key,
                algorithms=list(self.algorithms),
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "iss", "sub"]},
            )
            subject = claims.get("sub")
            tenant_id = claims.get(self.tenant_claim)
            roles = claims.get(self.roles_claim, [])
            if not isinstance(subject, str) or not isinstance(tenant_id, str) or not isinstance(roles, list):
                raise ValueError("OIDC claims have invalid types")
            if not all(isinstance(role, str) for role in roles):
                raise ValueError("OIDC roles must be strings")
            return Principal.from_roles(subject, tenant_id, roles)
        except Exception as exc:
            if isinstance(exc, ControlPlaneAuthenticationError):
                raise
            raise ControlPlaneAuthenticationError("OIDC authentication failed") from exc

    def _key(self, kid: str) -> dict[str, Any]:
        document = self._document()
        for key in document.get("keys", []):
            if key.get("kid") == kid:
                return cast(dict[str, Any], key)
        # Refresh once so a signing-key rotation does not require a restart.
        document = self._document(force=True)
        for key in document.get("keys", []):
            if key.get("kid") == kid:
                return cast(dict[str, Any], key)
        raise ValueError("OIDC signing key is not trusted")

    def _document(self, *, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if not force and self._jwks is not None and now < self._jwks_expires_at:
                return self._jwks
            request = Request(self.jwks_url, headers={"Accept": "application/json"})
            with urlopen(request, timeout=5) as response:
                document = cast(dict[str, Any], json.loads(response.read()))
            if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
                raise ValueError("OIDC JWKS response is invalid")
            self._jwks = document
            self._jwks_expires_at = now + self.jwks_ttl_seconds
            return document
