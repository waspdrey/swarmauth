from __future__ import annotations

import io
import json

import swarmauth
from swarmauth.control_plane_http import ControlPlaneHTTPApp


def call(app, method: str, path: str, body: dict | None = None):
    payload = json.dumps(body or {}).encode()
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(payload)),
        "wsgi.input": io.BytesIO(payload),
        "HTTP_AUTHORIZATION": "Bearer test",
    }
    statuses: list[str] = []
    response = app(environ, lambda status, _headers: statuses.append(status))
    return statuses[0], json.loads(b"".join(response))


def test_authenticated_wsgi_api_routes_through_rbac_and_tenant_store() -> None:
    store = swarmauth.ControlPlane()
    operator = swarmauth.Principal.from_roles("operator", "tenant-a", ["operator"])
    resolver_calls: list[str] = []

    def resolver(headers):
        resolver_calls.append(headers["authorization"])
        return operator

    app = ControlPlaneHTTPApp(resolver, lambda tenant_id: store if tenant_id == "tenant-a" else swarmauth.ControlPlane())
    keys = swarmauth.KeyPair.generate()
    status, result = call(
        app,
        "POST",
        "/agents",
        {"agent_id": "agent:a", "owner": "team-a", "public_key_hex": keys.public_bytes.hex()},
    )
    assert status == "201 Created"
    assert result["agent_id"] == "agent:a"
    status, result = call(app, "GET", "/agents")
    assert status == "200 OK" and len(result) == 1
    assert resolver_calls == ["Bearer test", "Bearer test"]


def test_wsgi_api_returns_auth_and_rbac_failures() -> None:
    def unauthenticated(_headers):
        raise swarmauth.ControlPlaneAuthenticationError("invalid access token")

    app = ControlPlaneHTTPApp(unauthenticated, lambda _tenant_id: swarmauth.ControlPlane())
    assert call(app, "GET", "/agents")[0] == "401 Unauthorized"

    viewer = swarmauth.Principal.from_roles("viewer", "tenant-a", ["viewer"])
    app = ControlPlaneHTTPApp(lambda _headers: viewer, lambda _tenant_id: swarmauth.ControlPlane())
    status, _ = call(app, "POST", "/tools", {"tool_id": "tool:x", "owner": "team", "capabilities": ["tool:x"]})
    assert status == "403 Forbidden"

    invalid = ControlPlaneHTTPApp(lambda _headers: object(), lambda _tenant_id: swarmauth.ControlPlane())
    assert call(invalid, "GET", "/agents")[0] == "401 Unauthorized"
