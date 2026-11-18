"""Signed decision and execution-outcome receipts for authorization audits."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Literal, Mapping, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from swarmauth.crypto import KeyPair, b64url_decode, b64url_encode, generate_jti, verify_signature
from swarmauth.events import AuthorizationDecision
from swarmauth.exceptions import InvalidSignatureError, MalformedTokenError

RECEIPT_TYPE = "SAR"
RECEIPT_ALG = "EdDSA"


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def receipt_hash(receipt: str) -> str:
    """Content identifier for chaining a later outcome to its decision."""
    return hashlib.sha256(receipt.encode("ascii")).hexdigest()


class ReceiptClaims(BaseModel):
    version: str = "1.0"
    receipt_type: Literal["authorization_decision", "execution_outcome"]
    receipt_id: str = Field(default_factory=generate_jti)
    issuer: str
    issued_at: int
    subject: Optional[str] = None
    envelope_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    approval_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    decision_receipt_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    data: dict[str, Any]

    model_config = ConfigDict(extra="forbid", frozen=True)


class ReceiptSink(Protocol):
    def __call__(self, receipt: str) -> None: ...


class SignedReceipt:
    """Compact Ed25519 receipt with a fixed algorithm and strict schema."""

    @staticmethod
    def issue(*, signer: KeyPair, claims: ReceiptClaims) -> str:
        header = {"alg": RECEIPT_ALG, "typ": RECEIPT_TYPE, "kid": signer.public_key_id}
        header_b64 = b64url_encode(_canonical_json(header))
        payload_b64 = b64url_encode(_canonical_json(claims.model_dump(mode="json", exclude_none=True)))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        return f"{header_b64}.{payload_b64}.{b64url_encode(signer.sign(signing_input))}"

    @staticmethod
    def verify(receipt: str, *, signer_public_key: bytes) -> ReceiptClaims:
        try:
            parts = receipt.split(".")
            if len(parts) != 3:
                raise MalformedTokenError("receipt must have exactly three segments")
            header = json.loads(b64url_decode(parts[0]))
            payload = json.loads(b64url_decode(parts[1]))
            signature = b64url_decode(parts[2])
            if not isinstance(header, dict) or header.get("alg") != RECEIPT_ALG or header.get("typ") != RECEIPT_TYPE:
                raise MalformedTokenError("receipt header is invalid")
            kid = b64url_decode(str(header.get("kid", "")))
            if kid != signer_public_key:
                raise InvalidSignatureError("receipt kid does not match the trusted signer")
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            verify_signature(signer_public_key, signing_input, signature)
            return ReceiptClaims.model_validate(payload)
        except (MalformedTokenError, InvalidSignatureError):
            raise
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
            raise MalformedTokenError("receipt is malformed") from exc


def issue_decision_receipt(
    decision: AuthorizationDecision,
    *,
    signer: KeyPair,
    issuer: str,
    envelope_hash: Optional[str] = None,
    approval_hash: Optional[str] = None,
    now: Optional[int] = None,
) -> str:
    """Sign an allow/deny decision without embedding its bearer credential."""
    claims = ReceiptClaims(
        receipt_type="authorization_decision",
        issuer=issuer,
        issued_at=int(time.time()) if now is None else now,
        subject=decision.subject,
        envelope_hash=envelope_hash,
        approval_hash=approval_hash,
        data=decision.as_dict(),
    )
    return SignedReceipt.issue(signer=signer, claims=claims)


def issue_outcome_receipt(
    *,
    signer: KeyPair,
    issuer: str,
    decision_receipt: str,
    status: Literal["succeeded", "failed", "cancelled"],
    metadata: Optional[Mapping[str, Any]] = None,
    subject: Optional[str] = None,
    now: Optional[int] = None,
) -> str:
    """Sign an execution outcome and cryptographically link it to its decision."""
    claims = ReceiptClaims(
        receipt_type="execution_outcome",
        issuer=issuer,
        issued_at=int(time.time()) if now is None else now,
        subject=subject,
        decision_receipt_hash=receipt_hash(decision_receipt),
        data={"status": status, "metadata": dict(metadata or {})},
    )
    return SignedReceipt.issue(signer=signer, claims=claims)
