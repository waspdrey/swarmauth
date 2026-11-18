"""Final-consequence authorization at the protected execution boundary."""
from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from typing import Any, Callable, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from swarmauth.approvals import ApprovalEvidence
from swarmauth.envelope import AuthorizationEnvelope
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError, TokenExpiredError, TokenRevokedError
from swarmauth.identity import ExecutionIdentityEvidence, ExecutionIdentityVerifier, VerifiedExecutionIdentity
from swarmauth.revocation import RevocationStore
from swarmauth.token import capability_covered, strict_value_equal


def _payload_hash(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class FinalConsequenceDecision(BaseModel):
    authorization_id: str
    envelope_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    payload_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    target: str
    capability: str
    resource_version: Optional[str] = None
    execution_identity: Optional[VerifiedExecutionIdentity] = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class InMemoryConsequenceStore:
    """Atomic single-action consumption for approval-bound authorizations."""

    def __init__(self) -> None:
        self._consumed: dict[str, int] = {}
        self._lock = threading.Lock()

    def consume(self, authorization_id: str, *, expires_at: int) -> None:
        with self._lock:
            now = time.time()
            self._consumed = {
                key: expiry for key, expiry in self._consumed.items() if expiry > now
            }
            if authorization_id in self._consumed:
                raise ConstraintViolationError(
                    "authorization was already consumed at a consequence boundary",
                    constraint="single_action",
                )
            self._consumed[authorization_id] = expires_at


class FinalConsequenceAuthorizer:
    """Re-evaluate authority against the exact payload and target before commit."""

    def __init__(
        self,
        *,
        revocation_store: Optional[RevocationStore] = None,
        identity_verifier: Optional[ExecutionIdentityVerifier] = None,
        approval_verifier: Optional[Callable[[ApprovalEvidence], bool]] = None,
        consequence_store: Optional[InMemoryConsequenceStore] = None,
    ) -> None:
        self._revocations = revocation_store
        self._identity_verifier = identity_verifier
        self._approval_verifier = approval_verifier
        self._consequences = consequence_store or InMemoryConsequenceStore()

    def authorize(
        self,
        envelope: AuthorizationEnvelope,
        *,
        capability: str,
        target: str,
        payload: Mapping[str, Any],
        amount: Optional[float] = None,
        challenge_nonce: Optional[str] = None,
        identity_evidence: Optional[ExecutionIdentityEvidence] = None,
        expected_resource_version: Optional[str] = None,
        actual_resource_version: Optional[str] = None,
        require_approval: bool = False,
        now: Optional[int] = None,
    ) -> FinalConsequenceDecision:
        try:
            payload_digest = _payload_hash(payload)
        except (TypeError, ValueError) as exc:
            raise ConstraintViolationError(
                "final payload must be finite canonical JSON",
                constraint="payload",
            ) from exc
        current = int(time.time()) if now is None else now
        validity = envelope.validity
        if current < validity.issued_at or current > validity.expires_at:
            raise TokenExpiredError("authorization envelope is outside its validity window")
        if self._revocations is not None and self._revocations.is_revoked(validity.authorization_id):
            raise TokenRevokedError(f"Authorization '{validity.authorization_id}' has been revoked")
        if target != envelope.mandate.subject:
            raise CapabilityViolationError(
                f"final target '{target}' does not match authorized subject '{envelope.mandate.subject}'",
                required=target,
            )
        if not capability_covered(capability, envelope.mandate.capabilities):
            raise CapabilityViolationError(
                f"authorization envelope does not grant '{capability}'",
                required=capability,
                granted=envelope.mandate.capabilities,
            )
        for key, expected in envelope.constraints.allowed_params.items():
            if key not in payload or not strict_value_equal(payload[key], expected):
                raise ConstraintViolationError(
                    f"final payload parameter '{key}' does not match the authorized value",
                    constraint="allowed_params",
                )
        amount_ceiling = envelope.constraints.max_amount_usd
        if amount_ceiling is not None:
            if amount is None or isinstance(amount, bool) or not isinstance(amount, (int, float)):
                raise ConstraintViolationError(
                    "final consequence requires a finite non-negative amount",
                    constraint="max_amount_usd",
                )
            parsed_amount = float(amount)
            if not math.isfinite(parsed_amount) or parsed_amount < 0 or parsed_amount > amount_ceiling:
                raise ConstraintViolationError(
                    f"final amount {amount!r} exceeds or violates the authorized ceiling",
                    constraint="max_amount_usd",
                )
        if expected_resource_version is not None and actual_resource_version != expected_resource_version:
            raise ConstraintViolationError(
                "protected resource changed after authorization",
                constraint="resource_version",
            )

        approval = envelope.approval_evidence
        if require_approval:
            if approval is None or approval.decision != "approved":
                raise ConstraintViolationError("final consequence requires approved evidence", constraint="approval")
            if self._approval_verifier is None or not self._approval_verifier(approval):
                raise ConstraintViolationError(
                    "approval evidence is not trusted by the consequence boundary",
                    constraint="approval",
                )
            if (
                approval.capability != capability
                or approval.subject != target
                or approval.requester != envelope.mandate.issuer
            ):
                raise ConstraintViolationError(
                    "approval evidence does not match the final mandate",
                    constraint="approval_binding",
                )
            if envelope.constraints.max_calls != 1:
                raise ConstraintViolationError(
                    "approval-bound consequences require max_calls=1",
                    constraint="single_action",
                )

        verified_identity: Optional[VerifiedExecutionIdentity] = None
        if self._identity_verifier is not None:
            if identity_evidence is None or challenge_nonce is None:
                raise ConstraintViolationError(
                    "execution identity evidence and challenge nonce are required",
                    constraint="execution_identity",
                )
            verified_identity = self._identity_verifier.verify(identity_evidence, expected_nonce=challenge_nonce)
            if verified_identity.agent_id != envelope.mandate.issuer:
                raise ConstraintViolationError(
                    "attested execution agent does not match the authorization mandate",
                    constraint="execution_identity",
                )

        if require_approval:
            self._consequences.consume(validity.authorization_id, expires_at=validity.expires_at)

        return FinalConsequenceDecision(
            authorization_id=validity.authorization_id,
            envelope_hash=envelope.digest(),
            payload_hash=payload_digest,
            target=target,
            capability=capability,
            resource_version=actual_resource_version,
            execution_identity=verified_identity,
        )
