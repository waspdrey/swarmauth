"""Minimal WSGI endpoint for signed human approval links."""
from __future__ import annotations

from html import escape
from typing import Any, Callable, Iterable, Mapping, Optional
from urllib.parse import parse_qs

from swarmauth.approvals import ApprovalGatekeeper, ApprovalStateError, ApprovalTokenError


class ApprovalHTTPApp:
    """Resolve one-click links behind an identity-aware reverse proxy.

    The proxy should set ``REMOTE_USER`` after SSO. Anonymous link use is
    disabled by default; enabling it explicitly makes the signed URL the
    reviewer credential and should only be used for a controlled pilot.
    """

    def __init__(self, gatekeeper: ApprovalGatekeeper, *, allow_anonymous_links: bool = False) -> None:
        self._gatekeeper = gatekeeper
        self._allow_anonymous_links = allow_anonymous_links

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        if str(environ.get("REQUEST_METHOD", "GET")).upper() != "GET":
            return self._respond(start_response, 405, "Method Not Allowed", "method_not_allowed")
        if str(environ.get("PATH_INFO", "/")) != "/approvals/resolve":
            return self._respond(start_response, 404, "Not Found", "not_found")
        token = parse_qs(str(environ.get("QUERY_STRING", ""))).get("token", [None])[0]
        if not token:
            return self._respond(start_response, 400, "Missing approval token", "invalid_request")
        # Only trust the server-authenticated WSGI identity. Do not accept an
        # arbitrary request header as an approver identity.
        approver = str(environ.get("REMOTE_USER", ""))
        if not approver and not self._allow_anonymous_links:
            return self._respond(start_response, 401, "Sign in before reviewing this action", "authentication_required")
        try:
            result = self._gatekeeper.resolve(token, approver=approver or "link-holder")
        except ApprovalTokenError:
            return self._respond(start_response, 400, "This approval link is invalid or expired", "invalid_token")
        except ApprovalStateError as exc:
            return self._respond(start_response, 409, str(exc), "already_decided")
        body = (
            "<!doctype html><meta charset=utf-8><title>SwarmAuth review</title>"
            f"<main><h1>Action {escape(result.status)}</h1>"
            f"<p>{escape(result.summary)}</p>"
            f"<p>Reviewed by <strong>{escape(result.approver or 'unknown')}</strong>.</p></main>"
        )
        return self._respond(start_response, 200, body, None, content_type="text/html; charset=utf-8")

    @staticmethod
    def _respond(
        start_response: Callable[..., Any],
        status: int,
        body: str,
        error: Optional[str],
        *,
        content_type: str = "application/json",
    ) -> list[bytes]:
        payload = body if error is None else '{"error":"' + error + '"}'
        raw = payload.encode("utf-8")
        phrases = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            404: "Not Found",
            405: "Method Not Allowed",
            409: "Conflict",
        }
        start_response(f"{status} {phrases[status]}", [("Content-Type", content_type), ("Content-Length", str(len(raw)))])
        return [raw]
