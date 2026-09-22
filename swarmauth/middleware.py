"""Execution-boundary enforcement: verify tokens and check constraints before
a tool actually runs, plus thin adapters for common agent frameworks.

The core primitive is `verify_and_check`, which is framework-agnostic. The
`guard` decorator and the framework adapters below are convenience wrappers
around it.
"""
from __future__ import annotations

import contextvars
import functools
import inspect
import math
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional, TypeVar

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError
from swarmauth.policy import IssuerPolicy
from swarmauth.registry import KeyRegistry
from swarmauth.revocation import RevocationStore
from swarmauth.token import CapabilityClaims, CapabilityToken, Constraints, check_capability, check_params

F = TypeVar("F", bound=Callable[..., Any])

# Kept past `exp` so a call accepted on the default 2-second leeway boundary
# still sees the same usage record. Entries are then eligible for collection.
_USAGE_RETENTION_AFTER_EXP_SECONDS = 3

_current_token: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("swarmauth_token", default=None)


@contextmanager
def use_token(token: str) -> Iterator[None]:
    """Attach `token` to the current context for guarded tool calls.

    Agent frameworks invoke a tool with the model's arguments and nothing
    else. The runtime — the code around the model, which the model does not
    control — enters this context with the token it was actually issued.
    `guard` reads it when the call has no token keyword argument.
    """
    if not isinstance(token, str) or not token:
        raise ValueError("token must be a non-empty string")
    reset = _current_token.set(token)
    try:
        yield
    finally:
        _current_token.reset(reset)


def _validated_amount(amount: Any) -> float:
    """Return a safe amount for cumulative-budget accounting.

    IEEE-754 non-finite values do not behave like ordinary monetary amounts:
    comparisons with ``nan`` are false, which could bypass a budget ceiling
    and poison subsequent accounting. Negative values would similarly reduce
    a cumulative spend total. They are never valid inputs to a ``max_amount``
    constraint.
    """
    try:
        parsed = float(amount)
    except (TypeError, ValueError) as exc:
        raise ConstraintViolationError(
            f"Amount {amount!r} is not a finite, non-negative number",
            constraint="max_amount_usd",
        ) from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ConstraintViolationError(
            f"Amount {amount!r} is not a finite, non-negative number",
            constraint="max_amount_usd",
        )
    return parsed


def _bound_call_params(signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    """Bind a call to its declared signature for constraint enforcement.

    ``kwargs`` alone is not a complete view of a Python call: parameter
    constraints must also apply when a caller supplies positional arguments.
    Flatten ``**kwargs`` so its individual runtime parameters remain visible
    to ``allowed_params``.
    """
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    params = dict(bound.arguments)
    for name, parameter in signature.parameters.items():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            params.update(params.pop(name, {}))
    return params


class TokenIssuer:
    """Signs tokens with one keypair, optionally refusing anything outside a policy.

    Pass `policy` in any process that holds the private key. Without it, this
    object will sign whatever it is asked to sign.
    """

    def __init__(self, keypair: KeyPair, policy: Optional[IssuerPolicy] = None):
        self.keypair = keypair
        self.policy = policy

    def issue(
        self,
        *,
        iss: str,
        sub: str,
        capabilities: list[str],
        constraints: Optional[Constraints] = None,
        ttl_seconds: int = 60,
        dlg: Optional[str] = None,
    ) -> str:
        resolved = constraints or Constraints()
        if self.policy is not None:
            self.policy.check(
                iss=iss,
                sub=sub,
                capabilities=capabilities,
                constraints=resolved,
                ttl_seconds=ttl_seconds,
                dlg=dlg,
            )
        return CapabilityToken.issue(
            issuer_keypair=self.keypair,
            iss=iss,
            sub=sub,
            capabilities=capabilities,
            constraints=resolved,
            ttl_seconds=ttl_seconds,
            dlg=dlg,
        )

    def attenuate(
        self,
        parent: str,
        *,
        iss: str,
        capabilities: list[str],
        constraints: Optional[Constraints] = None,
        ttl_seconds: int = 60,
    ) -> str:
        """Mint one narrower child of `parent` with this issuer's key."""
        resolved = constraints or Constraints()
        _header, parent_claims, _signing_input = CapabilityToken.parse(parent)
        if self.policy is not None:
            self.policy.check(
                iss=iss,
                sub=parent_claims.sub,
                capabilities=capabilities,
                constraints=resolved,
                ttl_seconds=ttl_seconds,
                dlg=None,
            )
        return CapabilityToken.attenuate(
            issuer_keypair=self.keypair,
            parent=parent,
            iss=iss,
            capabilities=capabilities,
            constraints=resolved,
            ttl_seconds=ttl_seconds,
        )


@dataclass
class _TokenUsage:
    call_count: int = 0
    spent_amount: float = 0.0
    call_timestamps: list[float] = field(default_factory=list)
    expires_at: float = 0.0


class UsageTracker:
    """In-memory, thread-safe tracker of per-token usage for constraint enforcement.

    Keyed by `jti`. This is process-local and non-durable, which fits
    SwarmAuth's <=300s token lifetime -- a token can't outlive the process
    worth tracking it against. For a distributed deployment, back this with
    Redis (or similar) behind the same `check_and_record` interface.
    """

    def __init__(self) -> None:
        self._usage: dict[str, _TokenUsage] = {}
        self._lock = threading.Lock()

    def _get(self, jti: str) -> _TokenUsage:
        return self._usage.setdefault(jti, _TokenUsage())

    def _purge_expired_unlocked(self, now: float) -> None:
        expired = [jti for jti, usage in self._usage.items() if usage.expires_at <= now]
        for jti in expired:
            del self._usage[jti]

    def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        with self._lock:
            now = time.time()
            self._purge_expired_unlocked(now)
            usage = self._get(claims.jti)
            usage.expires_at = max(usage.expires_at, float(claims.exp) + _USAGE_RETENTION_AFTER_EXP_SECONDS)
            constraints = claims.constraints

            if constraints.max_calls is not None and usage.call_count + 1 > constraints.max_calls:
                raise ConstraintViolationError(
                    f"Token {claims.jti} already used {usage.call_count}/{constraints.max_calls} calls",
                    constraint="max_calls",
                )

            if constraints.max_amount_usd is not None and usage.spent_amount + amount > constraints.max_amount_usd:
                remaining = constraints.max_amount_usd - usage.spent_amount
                raise ConstraintViolationError(
                    f"Amount {amount} would exceed remaining budget ({remaining:.2f} of {constraints.max_amount_usd})",
                    constraint="max_amount_usd",
                )

            if constraints.rate_limit_per_min is not None:
                window_start = now - 60
                recent = [t for t in usage.call_timestamps if t >= window_start]
                if len(recent) + 1 > constraints.rate_limit_per_min:
                    raise ConstraintViolationError(
                        f"Rate limit exceeded: {len(recent)}/{constraints.rate_limit_per_min} calls in last 60s",
                        constraint="rate_limit_per_min",
                    )
                usage.call_timestamps = recent

            usage.call_count += 1
            usage.spent_amount += amount
            usage.call_timestamps.append(now)


def verify_and_check(
    token: str,
    *,
    issuer_public_key: Optional[bytes] = None,
    key_registry: Optional[KeyRegistry] = None,
    revocation_store: Optional[RevocationStore] = None,
    audience: Optional[str] = None,
    required_capability: Optional[str] = None,
    amount: float = 0.0,
    params: Optional[dict[str, Any]] = None,
    tracker: Optional[UsageTracker] = None,
) -> CapabilityClaims:
    """Verify a token's signature/expiry/audience, check capability + constraints,
    and (if a tracker is given) atomically record usage against it.

    Exactly one of `issuer_public_key` or `key_registry` must be given -- see
    `CapabilityToken.verify` for the difference (single trusted key vs. a
    multi-issuer, rotation-aware registry).

    This is the single function every framework adapter below funnels into --
    it is the actual execution boundary, independent of whatever the calling
    agent's LLM decided to do.
    """
    claims = CapabilityToken.verify(
        token,
        issuer_public_key=issuer_public_key,
        key_registry=key_registry,
        revocation_store=revocation_store,
        audience=audience,
    )

    if required_capability is not None:
        check_capability(claims, required_capability)

    if params is not None:
        check_params(claims, params)

    stateful = [
        name
        for name, value in (
            ("max_calls", claims.constraints.max_calls),
            ("max_amount_usd", claims.constraints.max_amount_usd),
            ("rate_limit_per_min", claims.constraints.rate_limit_per_min),
        )
        if value is not None
    ]
    if stateful and tracker is None:
        raise ConstraintViolationError(
            f"Token declares {', '.join(stateful)} but no usage tracker was provided",
            constraint=stateful[0],
        )

    if tracker is not None:
        tracker.check_and_record(claims, amount=_validated_amount(amount))

    return claims


def guard(
    capability: str,
    *,
    issuer_public_key: Optional[bytes] = None,
    key_registry: Optional[KeyRegistry] = None,
    revocation_store: Optional[RevocationStore] = None,
    audience: Optional[str] = None,
    tracker: Optional[UsageTracker] = None,
    token_kwarg: str = "token",
    amount_kwarg: Optional[str] = None,
) -> Callable[[F], F]:
    """Execution-boundary guard: decorate a tool function so it verifies a
    JSON Capability Token before running, e.g. `@swarmauth.guard("tool:x", ...)`.

    Pass exactly one of `issuer_public_key` (single trusted issuer) or
    `key_registry` (many issuers, with key-rotation support -- see
    `swarmauth.registry.KeyRegistry`). Optionally pass a ``revocation_store``
    to reject a specifically revoked token before execution.

    The token is read from `token_kwarg` (default "token") when the caller
    passes it, and otherwise from the `use_token` context. It is stripped
    before the underlying function is invoked. `audience` defaults to
    `capability`, so a token for a different tool is rejected. Pass `audience`
    explicitly when the tool id and the capability string differ.

    Raises InvalidSignatureError / UnknownIssuerError / TokenExpiredError /
    CapabilityViolationError / ConstraintViolationError /
    AudienceMismatchError instead of executing the function.
    """
    bound_audience = capability if audience is None else audience

    def decorator(func: F) -> F:
        signature = inspect.signature(func)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            token = kwargs.pop(token_kwarg, None) or _current_token.get()
            if not token:
                raise CapabilityViolationError(
                    f"No JCT supplied (expected kwarg '{token_kwarg}' or use_token())", required=capability
                )

            params = _bound_call_params(signature, args, kwargs)
            amount = params.get(amount_kwarg, 0.0) if amount_kwarg else 0.0
            verify_and_check(
                token,
                issuer_public_key=issuer_public_key,
                key_registry=key_registry,
                revocation_store=revocation_store,
                audience=bound_audience,
                required_capability=capability,
                amount=amount,
                params=params,
                tracker=tracker,
            )
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Framework adapters
#
# None of langchain/crewai/autogen is a hard dependency of swarmauth. Each
# adapter secures the *execution* side (verifying incoming tokens) of a tool
# already registered with that framework; pair it with TokenIssuer on the
# calling agent's side to sign outgoing calls.
#
# IMPORTANT: the token must never be part of a tool's LLM-visible schema. If
# it were a normal parameter, the model itself could be prompted to omit,
# forge, or copy one from elsewhere in context -- exactly the trust boundary
# SwarmAuth exists to remove. Wrap the callable BEFORE the framework builds
# the tool's schema from its signature (frameworks generate schemas via
# `inspect.signature`, which follows `functools.wraps`'s `__wrapped__` link
# straight past the `token` kwarg these wrappers add), and have your own
# runtime -- not the model -- supply `token=...` when it invokes the
# underlying callable. `tests/test_framework_adapters.py` demonstrates this
# against real langchain-core and ag2 installs.
# ---------------------------------------------------------------------------


def secure_tool_call(
    func: Callable[..., Any],
    *,
    capability: str,
    issuer_public_key: Optional[bytes] = None,
    key_registry: Optional[KeyRegistry] = None,
    revocation_store: Optional[RevocationStore] = None,
    audience: Optional[str] = None,
    tracker: Optional[UsageTracker] = None,
    token_kwarg: str = "token",
    amount_kwarg: Optional[str] = None,
) -> Callable[..., Any]:
    """Framework-agnostic helper: wrap any callable (a LangChain tool's `func=`,
    a CrewAI `Tool`'s callable, an AutoGen registered function, or a plain
    Python function) so it verifies a JSON Capability Token before running.

    Equivalent to `guard` but expressed as a plain wrapping function, since
    most frameworks register a tool from an existing callable rather than
    letting you decorate a `def` in place. `amount_kwarg` names the wrapped
    function's parameter to read a spend amount from, for enforcing a
    token's `max_amount_usd` constraint -- without it, budget constraints
    are silently never charged for calls made through a framework adapter.
    """
    return guard(
        capability,
        issuer_public_key=issuer_public_key,
        key_registry=key_registry,
        revocation_store=revocation_store,
        audience=audience,
        tracker=tracker,
        token_kwarg=token_kwarg,
        amount_kwarg=amount_kwarg,
    )(func)


def secure_langchain_tool(tool: Any, **kwargs: Any) -> Any:
    """Wrap a LangChain `BaseTool` (or any object with a `.func`/`._run`) so its
    execution is gated on a valid JSON Capability Token. Duck-typed -- does not
    import langchain, so it works against any version with no hard dependency.
    """
    if getattr(tool, "func", None) is not None:
        tool.func = secure_tool_call(tool.func, **kwargs)
        return tool
    if hasattr(tool, "_run"):
        tool._run = secure_tool_call(tool._run, **kwargs)
        return tool
    raise TypeError(f"Object {tool!r} does not look like a LangChain tool (no .func or ._run)")


def secure_crewai_tool(tool: Any, **kwargs: Any) -> Any:
    """Wrap a CrewAI `Tool`/`BaseTool` the same way as `secure_langchain_tool` --
    CrewAI tools expose the same `.func` / `._run` shape.
    """
    return secure_langchain_tool(tool, **kwargs)


def secure_mcp_tool(func: Callable[..., Any], **kwargs: Any) -> Callable[..., Any]:
    """Wrap a plain function before registering it as a Model Context Protocol
    tool. MCP tool handlers are plain functions decorated at registration
    time (`@server.tool()`), the same shape as AutoGen/ag2's `@tool` --
    tested against a real `mcp.server.mcpserver.MCPServer` in
    tests/test_framework_adapters.py, which confirms the schema MCP exposes
    to the model omits `token` entirely (schema is built from the wrapped
    function's real signature via `__wrapped__`, added by `functools.wraps`)
    while the guard still enforces correctly when the tool is called:

        server.tool()(secure_mcp_tool(process_payout, capability="tool:process_payout", ...))
    """
    return secure_tool_call(func, **kwargs)


def secure_autogen_function(func: Callable[..., Any], **kwargs: Any) -> Callable[..., Any]:
    """Wrap a plain function before registering it as a tool with an AutoGen-family
    framework. The "AutoGen" name now covers several actively-diverging APIs
    (classic `pyautogen`'s `ConversableAgent.register_for_execution()`,
    Microsoft's rewritten `autogen-agentchat`, and the community `ag2` fork's
    `@ag2.tool` decorator) -- this adapter deliberately has zero framework
    import and just returns a guarded plain callable, so it composes with
    whichever registration mechanism your installed version uses:

        # ag2 (tested in tests/test_framework_adapters.py against a real install):
        tool = ag2.tool(secure_autogen_function(process_payout, ...))

        # classic pyautogen/ConversableAgent:
        agent.register_for_execution()(secure_autogen_function(process_payout, ...))

    See the note above on why the token must stay out of the function's
    LLM-visible schema either way.
    """
    return secure_tool_call(func, **kwargs)
