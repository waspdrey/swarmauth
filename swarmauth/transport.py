"""HTTP token propagation for ASGI (including FastAPI and HTTP MCP servers).

This middleware attaches an UNTRUSTED incoming credential to runtime context.
An endpoint/tool MUST use guard/async_guard for audience, capability, parameter,
revocation, and usage enforcement. Middleware alone never authorizes an action.
"""
from __future__ import annotations

import functools
import inspect
from typing import Any, Awaitable, Callable

from swarmauth.asyncio import async_guard
from swarmauth.exceptions import CapabilityViolationError
from swarmauth.middleware import _bound_call_params, guard, use_token

ASGIApp = Callable[[dict[str, Any], Callable[..., Any], Callable[..., Any]], Awaitable[None]]


class TokenContextMiddleware:
    def __init__(self, app: ASGIApp, *, max_token_bytes: int = 65536) -> None:
        if type(max_token_bytes) is not int or max_token_bytes < 1:
            raise ValueError("max_token_bytes must be positive")
        self.app, self.max_token_bytes = app, max_token_bytes

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Any], send: Callable[..., Any]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = [value for key, value in scope.get("headers", []) if key.lower() == b"authorization"]
        token = None
        if len(headers) == 1 and len(headers[0]) <= self.max_token_bytes + 7:
            try:
                scheme, value = headers[0].decode("ascii").split(" ", 1)
                if scheme.lower() == "bearer" and value and not any(char.isspace() for char in value):
                    token = value
            except (ValueError, UnicodeDecodeError):
                pass
        if token is None:
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
            await send({"type": "http.response.body", "body": b'{"error":"invalid_bearer_credential"}'})
            return
        with use_token(token):
            await self.app(scope, receive, send)


def secure_mcp_http_tool(
    func: Callable[..., Any], *, capability: str, context_kwarg: str = "ctx", **options: Any,
) -> Callable[..., Any]:
    """Use the MCP framework's injected per-message Context.headers credential.

    Include a Context-annotated argument on the original handler so the MCP
    framework injects it outside the model-visible schema. This does not reuse
    connection/session credentials for later requests. HTTP headers remain
    untrusted until the ordinary guard verifies them. Stdio has no header and
    is rejected; use secure_mcp_tool/use_token for that runtime instead.
    """
    signature = inspect.signature(func)
    if context_kwarg not in signature.parameters:
        raise TypeError("HTTP MCP tools require a framework-injected context argument")
    decorator = async_guard if inspect.iscoroutinefunction(func) else guard
    secured = decorator(capability, **options)(func)

    def credential(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        context = _bound_call_params(signature, args, kwargs).get(context_kwarg)
        headers = getattr(context, "headers", None)
        if headers is None:
            raise CapabilityViolationError("HTTP MCP request has no credential headers", required=capability)
        values = (headers.getlist("authorization") if hasattr(headers, "getlist") else
                  [value for key, value in headers.items() if key.lower() == "authorization"])
        if len(values) != 1 or not isinstance(values[0], str) or len(values[0]) > 65543:
            raise CapabilityViolationError("HTTP MCP request requires one bearer credential", required=capability)
        parts = values[0].split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1] or any(c.isspace() for c in parts[1]):
            raise CapabilityViolationError("Invalid HTTP MCP bearer credential", required=capability)
        return str(parts[1])

    if inspect.iscoroutinefunction(func):
        @functools.wraps(func)
        async def asynchronous(*args: Any, **kwargs: Any) -> Any:
            kwargs[options.get("token_kwarg", "token")] = credential(args, kwargs)
            return await secured(*args, **kwargs)
        return asynchronous

    @functools.wraps(func)
    def synchronous(*args: Any, **kwargs: Any) -> Any:
        kwargs[options.get("token_kwarg", "token")] = credential(args, kwargs)
        return secured(*args, **kwargs)
    return synchronous
