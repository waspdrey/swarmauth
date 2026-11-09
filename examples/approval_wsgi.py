"""Deployable approval-link WSGI application.

Required environment:

    SWARMAUTH_APPROVAL_SECRET=<32+ byte secret>
    SWARMAUTH_REVIEW_BASE_URL=https://review.example.com
    SWARMAUTH_APPROVAL_DB=/var/lib/swarmauth/approvals.db

Place this behind TLS and an SSO-aware reverse proxy that sets REMOTE_USER.
"""
from __future__ import annotations

from swarmauth.approval_wsgi import application  # noqa: F401
