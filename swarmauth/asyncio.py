"""Awaitable enforcement for network-backed stores and asynchronous tools."""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional, Sequence

from swarmauth.exceptions import CapabilityViolationError, SwarmAuthError, TokenRevokedError
from swarmauth.middleware import (
    AuthorizationEvent,
    _bound_call_params,
    _current_token,
    verify_and_check,
)
from swarmauth.token import CapabilityClaims, CapabilityToken


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class _Reservation:
    """Capture the already-verified chain without changing usage state."""

    def __init__(self) -> None:
        self.chain: Sequence[CapabilityClaims] = []
        self.amount = 0.0
        self.requires_chain = False
        self.supports_shared_budgets = False

    def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        self.check_and_record_chain([claims], amount=amount)

    def check_and_record_chain(self, chain: Sequence[CapabilityClaims], *, amount: float = 0.0) -> None:
        self.chain, self.amount = chain, amount


async def async_verify_and_check(token: str, **options: Any) -> CapabilityClaims:
    """Verify first, then await revocation, reservation, and decision delivery.

    Accepts the same options as ``verify_and_check``. Stores/callbacks may be
    synchronous or asynchronous. No tool execution occurs before all finish.
    """
    tracker = options.pop("tracker", None)
    store = options.pop("revocation_store", None)
    callback = options.pop("on_decision", None)
    reservation = _Reservation()
    reservation.requires_chain = bool(getattr(tracker, "requires_chain", False))
    reservation.supports_shared_budgets = bool(getattr(tracker, "supports_shared_budgets", False))
    claims = None
    try:
        claims = verify_and_check(token, tracker=reservation if tracker is not None else None, **options)
        chain = [CapabilityToken.parse(claims.prf)[1], claims] if claims.prf else [claims]
        if store is not None:
            for item in chain:
                if await _resolve(store.is_revoked(item.jti)):
                    raise TokenRevokedError(f"Token '{item.jti}' has been revoked")
        if tracker is not None:
            if len(reservation.chain) > 1:
                method = getattr(tracker, "check_and_record_chain", None)
                if not callable(method):
                    from swarmauth.exceptions import ConstraintViolationError
                    raise ConstraintViolationError("Delegated limits require atomic chain accounting", constraint="max_calls")
                await _resolve(method(reservation.chain, amount=reservation.amount))
            else:
                await _resolve(tracker.check_and_record(claims, amount=reservation.amount))
    except SwarmAuthError as exc:
        if callback is not None:
            await _resolve(callback(AuthorizationEvent(
                "denied", exc.code, claims.iss if claims else None, options.get("audience"),
                options.get("required_capability"), claims.jti if claims else None,
            )))
        raise
    if callback is not None:
        await _resolve(callback(AuthorizationEvent(
            "allowed", None, claims.iss, claims.sub, options.get("required_capability"), claims.jti,
        )))
    return claims


def async_guard(
    capability: str, *, audience: Optional[str] = None, token_kwarg: str = "token",
    amount_kwarg: Optional[str] = None, **options: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Guard a callable with awaited authorization and runtime token context."""
    bound_audience = capability if audience is None else audience

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(func)

        @functools.wraps(func)
        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            token = kwargs.pop(token_kwarg, None) or _current_token.get()
            if not token:
                callback = options.get("on_decision")
                if callback is not None:
                    await _resolve(callback(AuthorizationEvent(
                        "denied", "CAPABILITY_VIOLATION", None, bound_audience, capability, None,
                    )))
                raise CapabilityViolationError("No JCT supplied", required=capability)
            params = _bound_call_params(signature, args, kwargs)
            await async_verify_and_check(
                token, audience=bound_audience, required_capability=capability,
                params=params, amount=params.get(amount_kwarg) if amount_kwarg else None, **options,
            )
            return await _resolve(func(*args, **kwargs))

        return wrapped
    return decorate
