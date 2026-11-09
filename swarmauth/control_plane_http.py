"""Authenticated WSGI API seam for the SwarmAuth control plane."""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib.parse import parse_qs

from swarmauth.control_plane import ControlPlane, Principal, TenantControlPlane
from swarmauth.exceptions import ControlPlaneAccessError, ControlPlaneAuthenticationError


class PrincipalResolver(Protocol):
    """Resolve already-authenticated OAuth/OIDC request headers to a principal."""

    def __call__(self, headers: Mapping[str, str]) -> Principal: ...


class ControlPlaneHTTPApp:
    """Small WSGI application with injected identity and tenant storage.

    The resolver is responsible for validating OAuth/OIDC access tokens and
    constructing the principal. The app never parses or stores bearer tokens.
    ``store_for_tenant`` must return an isolated store for that tenant.
    """

    def __init__(self, resolver: PrincipalResolver, store_for_tenant: Callable[[str], ControlPlane]) -> None:
        self._resolver = resolver
        self._store_for_tenant = store_for_tenant

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))
        if method == "GET" and path == "/health":
            return self._respond(start_response, 200, {"ok": True})

        try:
            principal = self._resolver(self._headers(environ))
            if not isinstance(principal, Principal):
                raise ControlPlaneAuthenticationError("principal resolver returned an invalid principal")
            scoped = TenantControlPlane(principal.tenant_id, self._store_for(principal.tenant_id))
            if method == "GET" and path == "/agents":
                return self._respond(start_response, 200, [asdict(item) for item in scoped.agents(principal)])
            if method == "GET" and path == "/tools":
                return self._respond(start_response, 200, [asdict(item) for item in scoped.tools(principal)])
            if method == "GET" and path == "/decisions":
                query = parse_qs(str(environ.get("QUERY_STRING", "")))
                outcome = query.get("outcome", [None])[0]
                capability = query.get("capability", [None])[0]
                return self._respond(
                    start_response,
                    200,
                    [item.as_dict() for item in scoped.decisions(principal, outcome=outcome, capability=capability)],
                )
            if method == "POST" and path == "/agents":
                body = self._body(environ)
                agent_record = scoped.register_agent(
                    principal,
                    str(body["agent_id"]),
                    owner=str(body["owner"]),
                    public_key=bytes.fromhex(str(body["public_key_hex"])),
                    holder=bool(body.get("holder", False)),
                )
                return self._respond(start_response, 201, asdict(agent_record))
            if method == "POST" and path == "/tools":
                body = self._body(environ)
                tool_record = scoped.register_tool(
                    principal,
                    str(body["tool_id"]),
                    owner=str(body["owner"]),
                    capabilities=tuple(str(item) for item in body["capabilities"]),
                )
                return self._respond(start_response, 201, asdict(tool_record))
            return self._respond(start_response, 404, {"error": "not_found"})
        except ControlPlaneAuthenticationError as exc:
            return self._respond(start_response, 401, {"error": exc.code})
        except ControlPlaneAccessError as exc:
            return self._respond(start_response, 403, {"error": exc.code})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._respond(start_response, 400, {"error": str(exc)})

    @staticmethod
    def _headers(environ: Mapping[str, Any]) -> dict[str, str]:
        return {
            key[5:].replace("_", "-").lower(): str(value)
            for key, value in environ.items()
            if key.startswith("HTTP_")
        }

    @staticmethod
    def _body(environ: Mapping[str, Any]) -> dict[str, Any]:
        length = int(environ.get("CONTENT_LENGTH", "0") or "0")
        value = json.loads(environ["wsgi.input"].read(length))
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def _store_for(self, tenant_id: str) -> ControlPlane:
        store = self._store_for_tenant(tenant_id)
        if not isinstance(store, ControlPlane):
            raise TypeError("store_for_tenant must return a ControlPlane")
        return store

    @staticmethod
    def _respond(start_response: Callable[..., Any], status: int, value: Any) -> list[bytes]:
        body = json.dumps(value, sort_keys=True).encode("utf-8")
        phrase = {
            200: "OK", 201: "Created", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"
        }[status]
        start_response(
            f"{status} {phrase}",
            [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
        )
        return [body]
