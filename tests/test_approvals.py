import pytest

import swarmauth


def test_one_click_links_are_signed_single_use_and_channel_safe() -> None:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(
        action="issue_refund",
        capability="tool:refund",
        subject="agent:billing",
        requester="billing-agent",
        summary="Refund customer INV-100 for $250",
        now=100,
    )
    links = gate.links(request)
    assert "bearer" not in str(links).lower()
    message = swarmauth.SlackApprovalChannel().message(request, links["approve"], links["reject"])
    assert "Approve" in str(message)
    approved = gate.resolve(links["approve"].split("token=", 1)[1], approver="finance@example.com", now=101)
    assert approved.status == "approved"
    assert gate.require_approved(request.request_id).approver == "finance@example.com"
    with pytest.raises(swarmauth.ApprovalStateError):
        gate.resolve(links["approve"].split("token=", 1)[1], approver="other@example.com", now=102)


def test_tampering_and_expiry_fail_closed() -> None:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(
        action="deploy",
        capability="prod:deploy",
        subject="agent:release",
        requester="release-agent",
        summary="Deploy version 1.2.3",
        ttl_seconds=10,
        now=100,
    )
    token = gate.links(request)["approve"].split("token=", 1)[1]
    with pytest.raises(swarmauth.ApprovalTokenError):
        body, signature = token.split(".", 1)
        changed = ("a" if body[0] != "a" else "b") + body[1:]
        gate.resolve(f"{changed}.{signature}", approver="ops", now=101)
    with pytest.raises(swarmauth.ApprovalTokenError):
        gate.resolve(token, approver="ops", now=110)


def test_email_and_webhook_channels_render_without_credentials() -> None:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(action="write", capability="data:write", subject="a", requester="a", summary="Write record", now=1)
    links = gate.links(request)
    email = swarmauth.EmailApprovalChannel().message(request, links["approve"], links["reject"])
    sent = []
    swarmauth.WebhookApprovalChannel(sent.append).message(request, links["approve"], links["reject"])
    assert "bearer" not in str(email).lower()
    assert sent[0]["type"] == "swarmauth.approval_request"
