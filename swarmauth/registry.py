"""Key registry: maps issuer agent IDs to their trusted Ed25519 public key(s),
supporting zero-downtime key rotation and immediate revocation.

Without a registry, a verifier must hardcode one `issuer_public_key` per call
(fine for the two-agent examples in the README, unrealistic for a swarm with
many issuing agents). A `KeyRegistry` lets a verifier trust many issuers at
once and look the right key up by the token's `iss` claim -- and lets an
issuer rotate its signing key without a hard cutover: register the new key
with `rotate=True` and both keys verify until the old one is explicitly
revoked or the registry drops it.
"""
from __future__ import annotations

import threading

from swarmauth.exceptions import UnknownIssuerError


class KeyRegistry:
    """Thread-safe map of issuer agent ID -> trusted raw Ed25519 public key(s).

    Multiple keys can be valid for one issuer at once, newest first, so a
    verifier accepts tokens signed by either an issuer's current or
    just-superseded key during a rotation window.
    """

    def __init__(self) -> None:
        self._keys: dict[str, list[bytes]] = {}
        self._lock = threading.Lock()

    def register(self, iss: str, public_key: bytes, *, rotate: bool = False) -> None:
        """Trust `public_key` for issuer `iss`.

        `rotate=False` (default): this becomes the issuer's only trusted key,
        immediately invalidating any previously registered key for `iss` --
        use this for first registration or a hard key replacement.

        `rotate=True`: `public_key` is added ahead of the issuer's existing
        key(s) rather than replacing them, so tokens signed by the old key
        keep verifying during a rollover window. Call `revoke` once the old
        key is fully retired.
        """
        with self._lock:
            if rotate and iss in self._keys:
                existing = [k for k in self._keys[iss] if k != public_key]
                self._keys[iss] = [public_key, *existing]
            else:
                self._keys[iss] = [public_key]

    def revoke(self, iss: str, public_key: bytes) -> None:
        """Stop trusting `public_key` for `iss` immediately (e.g. a compromised key)."""
        with self._lock:
            remaining = [k for k in self._keys.get(iss, []) if k != public_key]
            if remaining:
                self._keys[iss] = remaining
            else:
                self._keys.pop(iss, None)

    def revoke_issuer(self, iss: str) -> None:
        """Stop trusting every key for `iss` (e.g. the agent itself is decommissioned)."""
        with self._lock:
            self._keys.pop(iss, None)

    def keys_for(self, iss: str) -> list[bytes]:
        """Return the trusted public key(s) for `iss`, newest first.

        Raises UnknownIssuerError if no key has ever been registered for
        `iss` -- distinct from a token failing signature verification, since
        an unrecognized issuer is a policy/registration gap, not a forgery.
        """
        with self._lock:
            keys = self._keys.get(iss)
        if not keys:
            raise UnknownIssuerError(f"No trusted key registered for issuer '{iss}'")
        return list(keys)

    def is_known(self, iss: str) -> bool:
        with self._lock:
            return iss in self._keys and bool(self._keys[iss])
