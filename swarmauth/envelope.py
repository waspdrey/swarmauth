"""Interoperable authorization envelopes and AAE-compatible field mapping."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field

from swarmauth.approvals import ApprovalEvidence
from swarmauth.token import CapabilityClaims, Constraints


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class AuthorizationMandate(BaseModel):
    """Who granted what authority to which execution subject."""

    issuer: str
    subject: str
    capabilities: list[str] = Field(..., min_length=1)
    delegate: Optional[str] = None
    parent_token_hash: Optional[str] = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorizationValidity(BaseModel):
    """Time and replay bounds for an authorization envelope."""

    issued_at: int
    expires_at: int
    authorization_id: str

    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorizationEnvelope(BaseModel):
    """Protocol-neutral MANDATE / CONSTRAINTS / VALIDITY representation.

    ``to_aae`` deliberately uses the uppercase section names from the Agent
    Authorization Envelope family while preserving SwarmAuth's native claims.
    The mapping is explicit and reversible; it is not a claim that either
    draft has standardized these exact inner field names.
    """

    version: str = "1.0"
    mandate: AuthorizationMandate
    constraints: Constraints = Field(default_factory=Constraints)
    validity: AuthorizationValidity
    approval_evidence: Optional[ApprovalEvidence] = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    @classmethod
    def from_claims(
        cls, claims: CapabilityClaims, *, approval_evidence: Optional[ApprovalEvidence] = None
    ) -> "AuthorizationEnvelope":
        parent_hash = hashlib.sha256(claims.prf.encode("ascii")).hexdigest() if claims.prf else None
        return cls(
            mandate=AuthorizationMandate(
                issuer=claims.iss,
                subject=claims.sub,
                capabilities=list(claims.capabilities),
                delegate=claims.dlg,
                parent_token_hash=parent_hash,
            ),
            constraints=claims.constraints,
            validity=AuthorizationValidity(
                issued_at=claims.iat,
                expires_at=claims.exp,
                authorization_id=claims.jti,
            ),
            approval_evidence=approval_evidence,
        )

    def to_aae(self) -> dict[str, Any]:
        """Return the interoperable AAE-shaped wire object."""
        mandate = self.mandate.model_dump(mode="json", exclude_none=True)
        result: dict[str, Any] = {
            "version": self.version,
            "MANDATE": mandate,
            "CONSTRAINTS": self.constraints.model_dump(mode="json", exclude_none=True),
            "VALIDITY": self.validity.model_dump(mode="json"),
        }
        if self.approval_evidence is not None:
            result["APPROVAL_EVIDENCE"] = self.approval_evidence.model_dump(mode="json")
        return result

    @classmethod
    def from_aae(cls, value: Mapping[str, Any]) -> "AuthorizationEnvelope":
        """Parse an AAE-shaped object and reject missing or unknown sections."""
        allowed = {"version", "MANDATE", "CONSTRAINTS", "VALIDITY", "APPROVAL_EVIDENCE"}
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown authorization envelope sections: {', '.join(sorted(unknown))}")
        return cls(
            version=str(value.get("version", "1.0")),
            mandate=AuthorizationMandate.model_validate(value["MANDATE"]),
            constraints=Constraints.model_validate(value.get("CONSTRAINTS", {})),
            validity=AuthorizationValidity.model_validate(value["VALIDITY"]),
            approval_evidence=(
                ApprovalEvidence.model_validate(value["APPROVAL_EVIDENCE"])
                if "APPROVAL_EVIDENCE" in value
                else None
            ),
        )

    def digest(self) -> str:
        """Stable SHA-256 identifier for receipts and cross-system transport."""
        return hashlib.sha256(_canonical_json(self.to_aae())).hexdigest()
