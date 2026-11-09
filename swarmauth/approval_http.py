"""Minimal WSGI endpoint for signed human approval links."""
from __future__ import annotations

from html import escape
from typing import Any, Callable, Iterable, Mapping, Optional, cast
from urllib.parse import parse_qs

from swarmauth.approvals import ApprovalGatekeeper, ApprovalStateError, ApprovalTokenError


class ApprovalHTTPApp:
    """Preview signed links on GET and resolve them on an explicit POST.

    The proxy should set ``REMOTE_USER`` after SSO. Anonymous link use is
    disabled by default; enabling it explicitly makes the signed URL the
    reviewer credential and should only be used for a controlled pilot.
    """

    def __init__(self, gatekeeper: ApprovalGatekeeper, *, allow_anonymous_links: bool = False) -> None:
        self._gatekeeper = gatekeeper
        self._allow_anonymous_links = allow_anonymous_links

    def __call__(self, environ: Mapping[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        if method not in {"GET", "POST"}:
            return self._respond(start_response, 405, "Method Not Allowed", "method_not_allowed")
        if str(environ.get("PATH_INFO", "/")) != "/approvals/resolve":
            return self._respond(start_response, 404, "Not Found", "not_found")
        token = parse_qs(str(environ.get("QUERY_STRING", ""))).get("token", [None])[0]
        if method == "POST":
            length = int(environ.get("CONTENT_LENGTH", "0") or "0")
            stream = cast(Any, environ.get("wsgi.input"))
            form = parse_qs(stream.read(length).decode("utf-8"))
            token = form.get("token", [token])[0]
        if not token:
            return self._respond(start_response, 400, "Missing approval token", "invalid_request")
        # Only trust the server-authenticated WSGI identity. Do not accept an
        # arbitrary request header as an approver identity.
        approver = str(environ.get("REMOTE_USER", ""))
        if not approver and not self._allow_anonymous_links:
            return self._respond(start_response, 401, "Sign in before reviewing this action", "authentication_required")
        try:
            request, decision = self._gatekeeper.preview(token)
            if request.status != "pending":
                return self._respond(start_response, 409, "This approval request is no longer pending", "already_decided")
            if method == "GET":
                body = (
                    "<!doctype html><meta charset=utf-8><title>SwarmAuth review</title>"
                    f"<main><h1>Review action: {escape(request.action)}</h1>"
                    f"<p>{escape(request.summary)}</p>"
                    f"<p>Requested by <strong>{escape(request.requester)}</strong>.</p>"
                    "<p>Confirm this decision:</p>"
                    "<form method='post' action='/approvals/resolve'>"
                    f"<input type='hidden' name='token' value='{escape(token, quote=True)}'>"
                    f"<button type='submit'>{escape(decision.title())}</button></form></main>"
                )
                return self._respond(start_response, 200, body, None, content_type="text/html; charset=utf-8")
            result = self._gatekeeper.resolve(token, approver=approver or "link-holder")
        except ApprovalTokenError:
            return self._respond(start_response, 400, "This approval link is invalid or expired", "invalid_token")
        except ApprovalStateError as exc:
            if "not found" in str(exc):
                return self._respond(start_response, 404, "Approval request not found", "not_found")
            return self._respond(start_response, 409, "This approval request is no longer pending", "already_decided")
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
