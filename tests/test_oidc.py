from __future__ import annotations

import json
import time

import pytest

import swarmauth

jwt = pytest.importorskip("jwt")


def test_oidc_resolver_validates_signature_and_maps_tenant_roles(monkeypatch) -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "key-1"
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "swarmauth",
            "sub": "user-1",
            "tenant_id": "tenant-a",
            "roles": ["auditor"],
            "iat": now,
            "exp": now + 60,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )

    def fake_urlopen(_request, timeout):
        assert timeout == 5

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def read(self):
                return json.dumps({"keys": [public_jwk]}).encode()

        return Response()

    monkeypatch.setattr("swarmauth.oidc.urlopen", fake_urlopen)
    resolver = swarmauth.OIDCPrincipalResolver(
        issuer="https://issuer.example", audience="swarmauth", jwks_url="https://issuer.example/jwks"
    )
    principal = resolver({"authorization": f"Bearer {token}"})
    assert principal.subject == "user-1"
    assert principal.tenant_id == "tenant-a"
    assert principal.roles == frozenset({"auditor"})


def test_oidc_resolver_fails_closed_for_tampered_token() -> None:
    resolver = swarmauth.OIDCPrincipalResolver(
        issuer="https://issuer.example", audience="swarmauth", jwks_url="https://issuer.example/jwks"
    )
    with pytest.raises(swarmauth.ControlPlaneAuthenticationError):
        resolver({"authorization": "Bearer not.a.jwt"})
