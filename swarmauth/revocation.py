"""Immediate, token-level revocation for incident response and offboarding.

The JCT format deliberately keeps tokens short lived, but a verifier must be
able to stop an otherwise valid token before its expiry when an agent, session,
or request is compromised. This module defines the small storage boundary used
by the core verifier. Applications may supply their own durable/distributed
implementation; ``InMemoryRevocationStore`` is suitable for a single process.
"""
from __future__ import annotations

import threading
import time
from typing import Protocol


class RevocationStore(Protocol):
    """Storage boundary for token IDs revoked through their expiry time."""

    def revoke(self, jti: str, *, expires_at: int) -> None:
        """Revoke ``jti`` until its signed Unix expiry time."""

    def is_revoked(self, jti: str) -> bool:
        """Return whether ``jti`` is currently revoked."""


class InMemoryRevocationStore:
    """Thread-safe, process-local ``RevocationStore`` with automatic expiry.

    Use a shared store such as ``RedisRevocationStore`` when more than one
    verifier process can accept the same token.
    """

    def __init__(self) -> None:
        self._revoked: dict[str, int] = {}
        self._lock = threading.Lock()

    def _purge_expired_unlocked(self, now: float) -> None:
        expired = [jti for jti, expires_at in self._revoked.items() if expires_at <= now]
        for jti in expired:
            del self._revoked[jti]

    def revoke(self, jti: str, *, expires_at: int) -> None:
        now = time.time()
        with self._lock:
            self._purge_expired_unlocked(now)
            if expires_at <= now:
                return
            self._revoked[jti] = max(expires_at, self._revoked.get(jti, 0))

    def is_revoked(self, jti: str) -> bool:
        now = time.time()
        with self._lock:
            self._purge_expired_unlocked(now)
            return jti in self._revoked
