"""Structured authorization decisions emitted by the execution boundary."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional, Protocol


@dataclass(frozen=True)
class AuthorizationDecision:
    """Safe-to-export outcome metadata; the bearer token is never included."""

    timestamp: float
    outcome: Literal["allow", "deny"]
    capability: Optional[str]
    audience: Optional[str]
    issuer: Optional[str]
    subject: Optional[str]
    jti: Optional[str]
    reason: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "outcome": self.outcome,
            "capability": self.capability,
            "audience": self.audience,
            "issuer": self.issuer,
            "subject": self.subject,
            "jti": self.jti,
            "reason": self.reason,
        }

    @classmethod
    def allowed(
        cls, *, capability: Optional[str], audience: Optional[str], issuer: str, subject: str, jti: str
    ) -> "AuthorizationDecision":
        return cls(time.time(), "allow", capability, audience, issuer, subject, jti)

    @classmethod
    def denied(cls, *, capability: Optional[str], audience: Optional[str], reason: str) -> "AuthorizationDecision":
        return cls(time.time(), "deny", capability, audience, None, None, None, reason)


class DecisionSink(Protocol):
    """Callable sink for shipping decisions to a logger, queue, or control plane."""

    def __call__(self, decision: AuthorizationDecision) -> None: ...


class JsonlDecisionSink:
    """Append decisions as one JSON object per line for local pilots or shipping."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __call__(self, decision: AuthorizationDecision) -> None:
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(decision.as_dict(), sort_keys=True) + "\n")
