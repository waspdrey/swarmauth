"""Send a human approval request to Slack and email.

This example expects the caller to supply a real gatekeeper request. It keeps
provider secrets in environment variables and never puts them in the approval
payload or URL.
"""
from __future__ import annotations

import os

import swarmauth


def create_and_notify_reviewers() -> swarmauth.ApprovalRequest:
    gate = swarmauth.ApprovalGatekeeper(
        secret=os.environ["SWARMAUTH_APPROVAL_SECRET"].encode("utf-8"),
        base_url=os.environ["SWARMAUTH_REVIEW_BASE_URL"],
    )

    request = gate.request(
        action="issue_refund", capability="tool:refund", subject="agent:billing",
        requester="billing-agent", summary="Refund INV-100 for $2,500",
    )
    gate.notify(request, swarmauth.SlackWebhookChannel(os.environ["SWARMAUTH_SLACK_WEBHOOK_URL"]))
    gate.notify(
        request,
        swarmauth.SMTPEmailChannel(
            os.environ["SWARMAUTH_SMTP_HOST"],
            sender=os.environ["SWARMAUTH_EMAIL_FROM"],
            recipients=tuple(os.environ["SWARMAUTH_EMAIL_TO"].split(",")),
            username=os.environ.get("SWARMAUTH_SMTP_USERNAME"),
            password=os.environ.get("SWARMAUTH_SMTP_PASSWORD"),
        ),
    )
    return request
