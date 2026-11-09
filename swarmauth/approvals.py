"""Human approval gates for high-stakes agent actions.

Channels deliver signed, expiring, single-use links. They never receive a
bearer token or decide authorization themselves; the gatekeeper remains the
source of truth for the action and its final state.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
from dataclasses import dataclass
from email.message import EmailMessage
from html import escape
from typing import Callable, Dict, Mapping, Optional, Protocol, TypedDict, cast
from urllib.request import Request, urlopen

from swarmauth.exceptions import ApprovalError


class ApprovalTokenError(ApprovalError):
    code = "APPROVAL_TOKEN_INVALID"


class ApprovalStateError(ApprovalError):
    code = "APPROVAL_STATE_INVALID"


class ApprovalPayload(TypedDict):
    rid: str
    decision: str
    exp: int
    nonce: str


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: str
    action: str
    capability: str
    subject: str
    requester: str
    summary: str
    expires_at: int
    status: str = "pending"
    approver: Optional[str] = None
    decided_at: Optional[int] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "capability": self.capability,
            "subject": self.subject,
            "requester": self.requester,
            "summary": self.summary,
            "expires_at": self.expires_at,
            "status": self.status,
            "approver": self.approver,
            "decided_at": self.decided_at,
        }


class ApprovalStore(Protocol):
    def create(self, request: ApprovalRequest) -> None: ...

    def get(self, request_id: str) -> Optional[ApprovalRequest]: ...

    def decide(self, request_id: str, status: str, approver: str, now: int) -> ApprovalRequest: ...


class InMemoryApprovalStore:
    """Small pilot store; replace with a transactional database in production."""

    def __init__(self) -> None:
        self._requests: Dict[str, ApprovalRequest] = {}
        self._lock = threading.RLock()

    def create(self, request: ApprovalRequest) -> None:
        with self._lock:
            if request.request_id in self._requests:
                raise ApprovalStateError("approval request already exists")
            self._requests[request.request_id] = request

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            return self._requests.get(request_id)

    def decide(self, request_id: str, status: str, approver: str, now: int) -> ApprovalRequest:
        with self._lock:
            current = self._requests.get(request_id)
            if current is None:
                raise ApprovalStateError("approval request not found")
            if current.status != "pending":
                raise ApprovalStateError("approval request was already decided")
            if now >= current.expires_at:
                self._requests[request_id] = ApprovalRequest(
                    request_id=current.request_id, action=current.action, capability=current.capability,
                    subject=current.subject, requester=current.requester, summary=current.summary,
                    expires_at=current.expires_at, status="expired",
                )
                raise ApprovalStateError("approval request has expired")
            if status not in {"approved", "rejected"}:
                raise ApprovalStateError("invalid approval state")
            decided = ApprovalRequest(
                request_id=current.request_id, action=current.action, capability=current.capability,
                subject=current.subject, requester=current.requester, summary=current.summary,
                expires_at=current.expires_at, status=status, approver=approver, decided_at=now,
            )
            self._requests[request_id] = decided
            return decided


class SQLiteApprovalStore:
    """Durable approval store with compare-and-set decisions."""

    def __init__(self, path: str) -> None:
        self._lock = threading.RLock()
        self._database = sqlite3.connect(path, check_same_thread=False)
        self._database.execute("PRAGMA journal_mode=WAL")
        self._database.execute(
            """CREATE TABLE IF NOT EXISTS approval_requests (
                request_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                capability TEXT NOT NULL,
                subject TEXT NOT NULL,
                requester TEXT NOT NULL,
                summary TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                approver TEXT,
                decided_at INTEGER
            )"""
        )
        self._database.commit()

    def create(self, request: ApprovalRequest) -> None:
        with self._lock:
            try:
                self._database.execute(
                    "INSERT INTO approval_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        request.request_id,
                        request.action,
                        request.capability,
                        request.subject,
                        request.requester,
                        request.summary,
                        request.expires_at,
                        request.status,
                        request.approver,
                        request.decided_at,
                    ),
                )
                self._database.commit()
            except sqlite3.IntegrityError as exc:
                self._database.rollback()
                raise ApprovalStateError("approval request already exists") from exc

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            row = self._database.execute(
                "SELECT request_id, action, capability, subject, requester, summary, expires_at, status, approver, decided_at "
                "FROM approval_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            return self._from_row(row) if row is not None else None

    def decide(self, request_id: str, status: str, approver: str, now: int) -> ApprovalRequest:
        if status not in {"approved", "rejected"}:
            raise ApprovalStateError("invalid approval state")
        with self._lock:
            try:
                self._database.execute("BEGIN IMMEDIATE")
                current = self.get(request_id)
                if current is None:
                    raise ApprovalStateError("approval request not found")
                if current.status != "pending":
                    raise ApprovalStateError("approval request was already decided")
                if now >= current.expires_at:
                    self._database.execute("UPDATE approval_requests SET status = 'expired' WHERE request_id = ?", (request_id,))
                    self._database.commit()
                    raise ApprovalStateError("approval request has expired")
                cursor = self._database.execute(
                    "UPDATE approval_requests SET status = ?, approver = ?, decided_at = ? "
                    "WHERE request_id = ? AND status = 'pending'",
                    (status, approver, now, request_id),
                )
                if cursor.rowcount != 1:
                    raise ApprovalStateError("approval request was already decided")
                self._database.commit()
                result = self.get(request_id)
                if result is None:
                    raise ApprovalStateError("approval request disappeared")
                return result
            except ApprovalStateError:
                self._database.rollback()
                raise
            except Exception:
                self._database.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._database.close()

    @staticmethod
    def _from_row(row: tuple[object, ...]) -> ApprovalRequest:
        return ApprovalRequest(
            request_id=str(row[0]),
            action=str(row[1]),
            capability=str(row[2]),
            subject=str(row[3]),
            requester=str(row[4]),
            summary=str(row[5]),
            expires_at=int(cast(int, row[6])),
            status=str(row[7]),
            approver=None if row[8] is None else str(row[8]),
            decided_at=None if row[9] is None else int(cast(int, row[9])),
        )


class ApprovalChannel(Protocol):
    def message(self, request: ApprovalRequest, approve_url: str, reject_url: str) -> Mapping[str, object]: ...


class SlackApprovalChannel:
    """Render a Slack Block Kit message with signed review links."""

    def message(self, request: ApprovalRequest, approve_url: str, reject_url: str) -> Mapping[str, object]:
        return {
            "text": f"Approval required: {request.action}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{request.summary}*"}},
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"Requested by `{request.requester}` · subject `{request.subject}`"}
                    ],
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Approve"},
                            "style": "primary",
                            "url": approve_url,
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Reject"},
                            "style": "danger",
                            "url": reject_url,
                        },
                    ],
                },
            ],
        }


class SlackWebhookChannel(SlackApprovalChannel):
    """Post a Block Kit approval message to an incoming Slack webhook."""

    def __init__(
        self,
        webhook_url: str,
        *,
        timeout: float = 5.0,
        post: Optional[Callable[[str, Mapping[str, object], float], None]] = None,
    ) -> None:
        self._webhook_url = webhook_url
        self._timeout = timeout
        self._post = post or self._post_json

    def message(self, request: ApprovalRequest, approve_url: str, reject_url: str) -> Mapping[str, object]:
        payload = super().message(request, approve_url, reject_url)
        self._post(self._webhook_url, payload, self._timeout)
        return payload

    @staticmethod
    def _post_json(url: str, payload: Mapping[str, object], timeout: float) -> None:
        body = json.dumps(payload).encode("utf-8")
        request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=timeout) as response:
            if not 200 <= response.status < 300:
                raise ApprovalError(f"Slack webhook returned HTTP {response.status}")


class EmailApprovalChannel:
    """Render a plain-text and HTML email; an email provider sends the result."""

    def message(self, request: ApprovalRequest, approve_url: str, reject_url: str) -> Mapping[str, object]:
        return {
            "subject": f"Approval required: {request.action}",
            "text": f"{request.summary}\n\nApprove: {approve_url}\nReject: {reject_url}",
            "html": (
                f'<p>{escape(request.summary)}</p><p>'
                f'<a href="{escape(approve_url, quote=True)}">Approve</a> · '
                f'<a href="{escape(reject_url, quote=True)}">Reject</a></p>'
            ),
        }


class SMTPEmailChannel(EmailApprovalChannel):
    """Send approval email through SMTP with TLS enabled by default."""

    def __init__(
        self,
        host: str,
        *,
        sender: str,
        recipients: tuple[str, ...],
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        starttls: bool = True,
        smtp_factory: Callable[..., smtplib.SMTP] = smtplib.SMTP,
        tls_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        if not recipients:
            raise ValueError("at least one approval email recipient is required")
        if (username is None) != (password is None):
            raise ValueError("SMTP username and password must be provided together")
        self._host = host
        self._sender = sender
        self._recipients = recipients
        self._port = port
        self._username = username
        self._password = password
        self._starttls = starttls
        self._smtp_factory = smtp_factory
        self._tls_context = tls_context or ssl.create_default_context()

    def message(self, request: ApprovalRequest, approve_url: str, reject_url: str) -> Mapping[str, object]:
        payload = super().message(request, approve_url, reject_url)
        email = EmailMessage()
        email["Subject"] = str(payload["subject"])
        email["From"] = self._sender
        email["To"] = ", ".join(self._recipients)
        email.set_content(str(payload["text"]))
        email.add_alternative(str(payload["html"]), subtype="html")
        with self._smtp_factory(self._host, self._port, timeout=10) as client:
            if self._starttls:
                client.starttls(context=self._tls_context)
            if self._username is not None and self._password is not None:
                client.login(self._username, self._password)
            client.send_message(email)
        return payload


class WebhookApprovalChannel:
    """Deliver the same provider-neutral approval card through any webhook."""

    def __init__(self, send: Callable[[Mapping[str, object]], None]) -> None:
        self._send = send

    def message(self, request: ApprovalRequest, approve_url: str, reject_url: str) -> Mapping[str, object]:
        payload = {
            "type": "swarmauth.approval_request",
            "request": request.as_dict(),
            "approve_url": approve_url,
            "reject_url": reject_url,
        }
        self._send(payload)
        return payload


class ApprovalGatekeeper:
    """Create and resolve approvals without exposing credentials to reviewers."""

    def __init__(self, *, secret: bytes, store: Optional[ApprovalStore] = None, base_url: str = "") -> None:
        if len(secret) < 32:
            raise ValueError("approval secret must be at least 32 bytes")
        if not base_url:
            raise ValueError("base_url is required for one-click approval links")
        self._secret = secret
        self._store = store or InMemoryApprovalStore()
        self._base_url = base_url.rstrip("/")

    def request(
        self,
        *,
        action: str,
        capability: str,
        subject: str,
        requester: str,
        summary: str,
        ttl_seconds: int = 900,
        request_id: Optional[str] = None,
        now: Optional[int] = None,
    ) -> ApprovalRequest:
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("approval TTL must be between 1 and 3600 seconds")
        issued = int(time.time()) if now is None else now
        request = ApprovalRequest(
            request_id=request_id or secrets.token_urlsafe(16),
            action=action,
            capability=capability,
            subject=subject,
            requester=requester,
            summary=summary,
            expires_at=issued + ttl_seconds,
        )
        self._store.create(request)
        return request

    def links(self, request: ApprovalRequest) -> Mapping[str, str]:
        return {"approve": self._link(request, "approved"), "reject": self._link(request, "rejected")}

    def notify(self, request: ApprovalRequest, channel: ApprovalChannel) -> Mapping[str, object]:
        links = self.links(request)
        return channel.message(request, links["approve"], links["reject"])

    def resolve(self, token: str, *, approver: str, now: Optional[int] = None) -> ApprovalRequest:
        request, decision = self.preview(token, now=now)
        current_time = int(time.time()) if now is None else now
        return self._store.decide(request.request_id, decision, approver, current_time)

    def preview(self, token: str, *, now: Optional[int] = None) -> tuple[ApprovalRequest, str]:
        """Validate a link without changing state; safe for GET previews and scanners."""
        payload = self._decode(token)
        current_time = int(time.time()) if now is None else now
        if current_time >= int(payload["exp"]):
            raise ApprovalTokenError("approval link has expired")
        request = self._store.get(str(payload["rid"]))
        if request is None:
            raise ApprovalStateError("approval request not found")
        return request, str(payload["decision"])

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._store.get(request_id)

    def require_approved(self, request_id: str) -> ApprovalRequest:
        request = self._store.get(request_id)
        if request is None or request.status != "approved":
            raise ApprovalStateError("action requires an approved human review")
        return request

    def _link(self, request: ApprovalRequest, decision: str) -> str:
        payload = {"rid": request.request_id, "decision": decision, "exp": request.expires_at, "nonce": secrets.token_urlsafe(8)}
        return f"{self._base_url}/approvals/resolve?token={self._encode(payload)}"

    def _encode(self, payload: Mapping[str, object]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        body = base64.urlsafe_b64encode(raw).rstrip(b"=")
        signature = hmac.new(self._secret, body, hashlib.sha256).digest()
        sig = base64.urlsafe_b64encode(signature).rstrip(b"=")
        return f"{body.decode('ascii')}.{sig.decode('ascii')}"

    def _decode(self, token: str) -> ApprovalPayload:
        try:
            body_text, sig_text = token.split(".", 1)
            body = body_text.encode("ascii")
            signature = base64.urlsafe_b64decode(sig_text + "=" * (-len(sig_text) % 4))
            expected = hmac.new(self._secret, body, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ApprovalTokenError("approval link signature is invalid")
            payload = json.loads(base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4)))
            if not isinstance(payload, dict) or not {"rid", "decision", "exp", "nonce"}.issubset(payload):
                raise ApprovalTokenError("approval link payload is invalid")
            if payload["decision"] not in {"approved", "rejected"}:
                raise ApprovalTokenError("approval decision is invalid")
            return cast(ApprovalPayload, payload)
        except (ApprovalTokenError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            if isinstance(exc, ApprovalTokenError):
                raise
            raise ApprovalTokenError("approval link is malformed") from exc
