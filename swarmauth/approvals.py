"""Reusable approval grants bound to an exact resource revision and payload."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Optional, Protocol

from swarmauth.crypto import generate_jti
from swarmauth.exceptions import PolicyViolationError
from swarmauth.middleware import TokenIssuer, UsageBackend, verify_and_check
from swarmauth.registry import KeyRegistry
from swarmauth.revocation import RevocationStore
from swarmauth.token import CapabilityClaims, Constraints


def request_digest(payload: Any) -> str:
    """Hash portable JSON. Monetary fields must use integer minor units.

    Floats are deliberately excluded to avoid cross-language number formatting
    differences. This digest identifies a request; it does not authorize it.
    """
    def valid(value: Any) -> bool:
        if value is None or isinstance(value, (str, bool)):
            return True
        if type(value) is int:
            return abs(value) <= 2**53 - 1
        if isinstance(value, list):
            return all(valid(item) for item in value)
        return isinstance(value, dict) and all(isinstance(key, str) and valid(item) for key, item in value.items())
    if not valid(payload):
        raise ValueError("Approval payload must contain JSON with safe integers and no floats")
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Approval:
    id: str
    resource_id: str
    revision: str
    request_digest: str
    expires_at: int

    def pins(self) -> dict[str, Any]:
        return {"approval_id": self.id, "resource_id": self.resource_id,
                "revision": self.revision, "request_digest": self.request_digest}


class ApprovalStore(Protocol):
    def put(self, approval: Approval) -> None: ...
    def get(self, approval_id: str) -> Optional[Approval]: ...
    def is_active(self, approval: Approval) -> bool: ...
    def invalidate(self, resource_id: str) -> None: ...
    def consume(self, approval: Approval) -> bool: ...


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self._records: dict[str, Approval] = {}
        self._active: dict[str, str] = {}
        self._lock = threading.Lock()

    def put(self, approval: Approval) -> None:
        with self._lock:
            now = time.time()
            self._records = {key: item for key, item in self._records.items() if item.expires_at > now}
            self._active = {key: value for key, value in self._active.items() if value in self._records}
            self._records[approval.id] = approval
            self._active[approval.resource_id] = approval.id

    def get(self, approval_id: str) -> Optional[Approval]:
        with self._lock:
            return self._records.get(approval_id)

    def is_active(self, approval: Approval) -> bool:
        with self._lock:
            return self._active.get(approval.resource_id) == approval.id

    def invalidate(self, resource_id: str) -> None:
        with self._lock:
            self._active.pop(resource_id, None)

    def consume(self, approval: Approval) -> bool:
        with self._lock:
            if approval.expires_at <= time.time() or self._active.get(approval.resource_id) != approval.id:
                return False
            del self._active[approval.resource_id]
            return True


class RedisApprovalStore:
    def __init__(self, client: Any, *, key_prefix: str = "swarmauth:approval:") -> None:
        self.client, self.key_prefix = client, key_prefix

    def _key(self, kind: str, value: str) -> str:
        return self.key_prefix + kind + ":" + hashlib.sha256(value.encode()).hexdigest()

    def put(self, approval: Approval) -> None:
        ttl = max(1, approval.expires_at - int(time.time()))
        with self.client.pipeline() as pipe:
            pipe.set(self._key("record", approval.id), json.dumps(asdict(approval)), ex=ttl)
            pipe.set(self._key("resource", approval.resource_id), approval.id, ex=ttl)
            pipe.execute()

    def get(self, approval_id: str) -> Optional[Approval]:
        raw = self.client.get(self._key("record", approval_id))
        return Approval(**json.loads(raw)) if raw else None

    def is_active(self, approval: Approval) -> bool:
        current = self.client.get(self._key("resource", approval.resource_id))
        return (current.decode() if isinstance(current, bytes) else current) == approval.id

    def invalidate(self, resource_id: str) -> None:
        self.client.delete(self._key("resource", resource_id))

    def consume(self, approval: Approval) -> bool:
        import redis
        key = self._key("resource", approval.resource_id)
        with self.client.pipeline() as pipe:
            for _ in range(64):
                try:
                    pipe.watch(key)
                    current = pipe.get(key)
                    current = current.decode() if isinstance(current, bytes) else current
                    if current != approval.id or approval.expires_at <= time.time():
                        return False
                    pipe.multi()
                    pipe.delete(key)
                    pipe.execute()
                    return True
                except redis.WatchError:
                    continue
        raise PolicyViolationError("Approval contention exceeded retry limit")


class ApprovalService:
    """Keep this service and signing key outside model-accessible tools.

    approve() records a decision made by a trusted human/business service. It
    does not infer consent. Load current revisions from trusted storage before
    authorize(); invalidate on edits. Business-row locking and side-effect
    idempotency remain the application's transaction boundary.
    """

    def __init__(self, store: ApprovalStore) -> None:
        self.store = store

    def approve(self, resource_id: str, revision: str, payload: Any, *, expires_at: int) -> Approval:
        if not isinstance(resource_id, str) or not resource_id or not isinstance(revision, str) or not revision:
            raise ValueError("Approval requires resource_id and revision")
        if type(expires_at) is not int or expires_at <= time.time():
            raise ValueError("Approval must expire in the future")
        approval = Approval(generate_jti(), resource_id, revision, request_digest(payload), expires_at)
        self.store.put(approval)
        return approval

    def _active(self, approval_id: str) -> Approval:
        approval = self.store.get(approval_id)
        if approval is None or approval.expires_at <= time.time() or not self.store.is_active(approval):
            raise PolicyViolationError("Approval is absent, expired, superseded, or invalidated")
        return approval

    def issue(
        self, approval_id: str, *, issuer: TokenIssuer, iss: str, sub: str,
        capabilities: list[str], ttl_seconds: int = 10,
    ) -> str:
        approval = self._active(approval_id)
        remaining = approval.expires_at - int(time.time())
        if ttl_seconds > remaining:
            raise PolicyViolationError("Token would outlive the approval")
        return issuer.issue(
            iss=iss, sub=sub, capabilities=capabilities, ttl_seconds=ttl_seconds,
            constraints=Constraints(max_calls=1, allowed_params=approval.pins()),
        )

    def authorize(
        self, token: str, *, approval_id: str, resource_id: str, revision: str, payload: Any,
        audience: str, capability: str, tracker: UsageBackend, issuer_public_key: Optional[bytes] = None,
        key_registry: Optional[KeyRegistry] = None, revocation_store: Optional[RevocationStore] = None,
    ) -> CapabilityClaims:
        approval = self._active(approval_id)
        current = {"approval_id": approval_id, "resource_id": resource_id,
                   "revision": revision, "request_digest": request_digest(payload)}
        if current != approval.pins():
            raise PolicyViolationError("Approved request changed; obtain a new approval")
        claims = verify_and_check(
            token, issuer_public_key=issuer_public_key, key_registry=key_registry,
            audience=audience, required_capability=capability, params=current,
            tracker=tracker, revocation_store=revocation_store,
        )
        if not self.store.consume(approval):
            raise PolicyViolationError("Approval was consumed or invalidated before execution")
        return claims
