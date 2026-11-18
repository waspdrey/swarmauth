"""Final-consequence authorization at the protected execution boundary."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Callable, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from swarmauth.approvals import ApprovalEvidence
from swarmauth.envelope import AuthorizationEnvelope
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError, TokenExpiredError, TokenRevokedError
from swarmauth.identity import ExecutionIdentityEvidence, ExecutionIdentityVerifier, VerifiedExecutionIdentity
from swarmauth.revocation import RevocationStore
from swarmauth.token import capability_covered


def _payload_hash(value: Mapping[str, Any]) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
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
        self._consumed: set[str] = set()
        self._lock = threading.Lock()

    def consume(self, authorization_id: str) -> None:
        with self._lock:
            if authorization_id in self._consumed:
                raise ConstraintViolationError(
                    "authorization was already consumed at a consequence boundary",
                    constraint="single_action",
                )
            self._consumed.add(authorization_id)


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
        challenge_nonce: Optional[str] = None,
        identity_evidence: Optional[ExecutionIdentityEvidence] = None,
        expected_resource_version: Optional[str] = None,
        actual_resource_version: Optional[str] = None,
        require_approval: bool = False,
        now: Optional[int] = None,
    ) -> FinalConsequenceDecision:
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
            if payload.get(key) != expected:
                raise ConstraintViolationError(
                    f"final payload parameter '{key}' does not match the authorized value",
                    constraint="allowed_params",
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
            self._consequences.consume(validity.authorization_id)

        return FinalConsequenceDecision(
            authorization_id=validity.authorization_id,
            envelope_hash=envelope.digest(),
            payload_hash=_payload_hash(payload),
            target=target,
            capability=capability,
            resource_version=actual_resource_version,
            execution_identity=verified_identity,
        )
