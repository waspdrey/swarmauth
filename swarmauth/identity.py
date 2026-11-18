"""Pluggable proof-of-execution identity and runtime attestation boundary."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable, Mapping, Optional, Protocol

from pydantic import BaseModel, ConfigDict, Field


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class ExecutionIdentityEvidence(BaseModel):
    """Opaque attestation supplied by hardware, a TEE, or a cloud workload provider."""

    format: str
    agent_id: str
    key_id: str
    nonce: str
    issued_at: int
    evidence: dict[str, Any]

    model_config = ConfigDict(extra="forbid", frozen=True)

    def digest(self) -> str:
        return hashlib.sha256(_canonical_json(self.model_dump(mode="json"))).hexdigest()


class VerifiedExecutionIdentity(BaseModel):
    agent_id: str
    key_id: str
    attestation_format: str
    environment: Optional[str] = None
    evidence_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    verified_at: int

    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionIdentityVerifier(Protocol):
    def verify(
        self, evidence: ExecutionIdentityEvidence, *, expected_nonce: str
    ) -> VerifiedExecutionIdentity: ...


class CallbackIdentityVerifier:
    """Adapter for TPM, WebAuthn, TEE, SPIFFE, or cloud-attestation SDKs."""

    def __init__(self, validate: Callable[[ExecutionIdentityEvidence], Mapping[str, Any]]) -> None:
        self._validate = validate

    def verify(
        self, evidence: ExecutionIdentityEvidence, *, expected_nonce: str
    ) -> VerifiedExecutionIdentity:
        if evidence.nonce != expected_nonce:
            raise ValueError("execution identity nonce does not match the authorization challenge")
        claims = self._validate(evidence)
        if claims.get("agent_id") != evidence.agent_id or claims.get("key_id") != evidence.key_id:
            raise ValueError("attested identity does not match the supplied execution identity")
        return VerifiedExecutionIdentity(
            agent_id=evidence.agent_id,
            key_id=evidence.key_id,
            attestation_format=evidence.format,
            environment=str(claims["environment"]) if claims.get("environment") is not None else None,
            evidence_hash=evidence.digest(),
            verified_at=int(time.time()),
        )
