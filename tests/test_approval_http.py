import time
from io import BytesIO

import swarmauth


def call(app, *, query: str, remote_user: str = ""):
    result = {}

    def start(status, headers):
        result["status"] = status
        result["headers"] = headers

    body = app(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/approvals/resolve",
            "QUERY_STRING": query,
            "REMOTE_USER": remote_user,
            "wsgi.input": BytesIO(),
        },
        start,
    )
    return result["status"], b"".join(body).decode()


def test_authenticated_browser_link_resolves_and_replay_is_rejected() -> None:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(
        action="deploy",
        capability="prod:deploy",
        subject="agent:release",
        requester="release",
        summary="Deploy",
        now=int(time.time()),
    )
    token = gate.links(request)["approve"].split("token=", 1)[1]
    app = swarmauth.ApprovalHTTPApp(gate)
    status, body = call(app, query=f"token={token}", remote_user="alice@example.com")
    assert status == "200 OK"
    assert "approved" in body
    status, body = call(app, query=f"token={token}", remote_user="bob@example.com")
    assert status == "409 Conflict"
    assert "already_decided" in body


def test_http_requires_identity_unless_explicitly_enabled() -> None:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(
        action="delete",
        capability="data:delete",
        subject="agent:x",
        requester="x",
        summary="Delete",
        now=int(time.time()),
    )
    token = gate.links(request)["reject"].split("token=", 1)[1]
    status, body = call(swarmauth.ApprovalHTTPApp(gate), query=f"token={token}")
    assert status == "401 Unauthorized"
    assert "authentication_required" in body
    status, _ = call(swarmauth.ApprovalHTTPApp(gate, allow_anonymous_links=True), query=f"token={token}")
    assert status == "200 OK"
