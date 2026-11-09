"""Installed-package WSGI entrypoint for the approval review service."""
from __future__ import annotations

import os

from swarmauth.approval_http import ApprovalHTTPApp
from swarmauth.approvals import ApprovalGatekeeper, SQLiteApprovalStore

store = SQLiteApprovalStore(os.environ["SWARMAUTH_APPROVAL_DB"])
gatekeeper = ApprovalGatekeeper(
    secret=os.environ["SWARMAUTH_APPROVAL_SECRET"].encode("utf-8"),
    base_url=os.environ["SWARMAUTH_REVIEW_BASE_URL"],
    store=store,
)
application = ApprovalHTTPApp(gatekeeper)
