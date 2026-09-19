"""Execution-boundary enforcement: verify tokens and check constraints before
a tool actually runs, plus thin adapters for common agent frameworks.

The core primitive is `verify_and_check`, which is framework-agnostic. The
`guard` decorator and the framework adapters below are convenience wrappers
around it.
"""
from __future__ import annotations

import functools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, TypeVar

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError
from swarmauth.token import CapabilityClaims, CapabilityToken, Constraints, check_capability, check_params

F = TypeVar("F", bound=Callable[..., Any])


class TokenIssuer:
    """Convenience wrapper around CapabilityToken.issue bound to one keypair."""

    def __init__(self, keypair: KeyPair):
        self.keypair = keypair

    def issue(
        self,
        *,
        iss: str,
        sub: str,
        capabilities: list[str],
        constraints: Optional[Constraints] = None,
        ttl_seconds: int = 60,
    ) -> str:
        return CapabilityToken.issue(
            issuer_keypair=self.keypair,
            iss=iss,
            sub=sub,
            capabilities=capabilities,
            constraints=constraints,
            ttl_seconds=ttl_seconds,
        )


@dataclass
class _TokenUsage:
    call_count: int = 0
    spent_amount: float = 0.0
    call_timestamps: list = field(default_factory=list)


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

    def check_and_record(self, claims: CapabilityClaims, *, amount: float = 0.0) -> None:
        with self._lock:
            usage = self._get(claims.jti)
            constraints = claims.constraints
            now = time.time()

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
    issuer_public_key: bytes,
    audience: Optional[str] = None,
    required_capability: Optional[str] = None,
    amount: float = 0.0,
    params: Optional[dict[str, Any]] = None,
    tracker: Optional[UsageTracker] = None,
) -> CapabilityClaims:
    """Verify a token's signature/expiry/audience, check capability + constraints,
    and (if a tracker is given) atomically record usage against it.

    This is the single function every framework adapter below funnels into --
    it is the actual execution boundary, independent of whatever the calling
    agent's LLM decided to do.
    """
    claims = CapabilityToken.verify(token, issuer_public_key=issuer_public_key, audience=audience)

    if required_capability is not None:
        check_capability(claims, required_capability)

    if params:
        check_params(claims, params)

    if tracker is not None:
        tracker.check_and_record(claims, amount=amount)

    return claims


def guard(
    capability: str,
    *,
    issuer_public_key: bytes,
    audience: Optional[str] = None,
    tracker: Optional[UsageTracker] = None,
    token_kwarg: str = "token",
    amount_kwarg: Optional[str] = None,
) -> Callable[[F], F]:
    """Execution-boundary guard: decorate a tool function so it verifies a
    JSON Capability Token before running, e.g. `@swarmauth.guard("tool:x", ...)`.

    The wrapped function must be called with the token as a keyword argument
    (`token_kwarg`, default "token"); it is stripped before the underlying
    function is invoked. Raises InvalidSignatureError / TokenExpiredError /
    CapabilityViolationError / ConstraintViolationError instead of executing
    the function.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            token = kwargs.pop(token_kwarg, None)
            if not token:
                raise CapabilityViolationError(
                    f"No JCT supplied (expected kwarg '{token_kwarg}')", required=capability
                )

            amount = float(kwargs.get(amount_kwarg, 0.0)) if amount_kwarg else 0.0
            verify_and_check(
                token,
                issuer_public_key=issuer_public_key,
                audience=audience,
                required_capability=capability,
                amount=amount,
                params=kwargs,
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
    issuer_public_key: bytes,
    audience: Optional[str] = None,
    tracker: Optional[UsageTracker] = None,
    token_kwarg: str = "token",
) -> Callable[..., Any]:
    """Framework-agnostic helper: wrap any callable (a LangChain tool's `func=`,
    a CrewAI `Tool`'s callable, an AutoGen registered function, or a plain
    Python function) so it verifies a JSON Capability Token before running.

    Equivalent to `guard` but expressed as a plain wrapping function, since
    most frameworks register a tool from an existing callable rather than
    letting you decorate a `def` in place.
    """
    return guard(
        capability,
        issuer_public_key=issuer_public_key,
        audience=audience,
        tracker=tracker,
        token_kwarg=token_kwarg,
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
