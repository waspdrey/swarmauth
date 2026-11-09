"""Send a human approval request to Slack and email.

This example expects the caller to supply a real gatekeeper request. It keeps
provider secrets in environment variables and never puts them in the approval
payload or URL.
"""
from __future__ import annotations

import os

import swarmauth


def notify_reviewers(request: swarmauth.ApprovalRequest) -> None:
    gate = swarmauth.ApprovalGatekeeper(
        secret=os.environ["SWARMAUTH_APPROVAL_SECRET"].encode("utf-8"),
        base_url=os.environ["SWARMAUTH_REVIEW_BASE_URL"],
    )

    # The same request should normally be created by this gatekeeper instance;
    # this function demonstrates delivery wiring for an existing request.
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
