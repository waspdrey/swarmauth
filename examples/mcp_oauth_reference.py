"""Reference shape for protecting an MCP tool behind an OAuth resource server.

The OAuth authorization server and MCP transport remain owned by the deployment.
After that layer validates the incoming Authorization header, the runtime enters
``use_bearer_token`` before invoking the guarded MCP function. The bearer token
never appears in the model-visible tool schema.

Run this example after installing the optional MCP extra. It exercises the same
boundary without requiring a live OAuth provider:

    python examples/mcp_oauth_reference.py
"""
from __future__ import annotations

import asyncio

import swarmauth


def main() -> None:
    try:
        from mcp.server.mcpserver import MCPServer
        server = MCPServer("swarmauth-oauth-reference")
        list_tools = server.list_tools
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP
        except ImportError as exc:
            raise SystemExit("Install the optional MCP dependency with: pip install -e '.[frameworks]'") from exc
        server = FastMCP("swarmauth-oauth-reference")

        async def list_tools():
            return await server._tool_manager.list_tools()  # type: ignore[attr-defined]

    issuer_keys = swarmauth.KeyPair.generate()
    issuer = swarmauth.TokenIssuer(issuer_keys)
    decisions: list[swarmauth.AuthorizationDecision] = []

    # Register this wrapped function with the MCP server in the transport layer.
    def process_refund(invoice_id: str, amount_usd: float) -> str:
        return f"refunded {amount_usd} for {invoice_id}"

    guarded = swarmauth.secure_mcp_tool(
        process_refund,
        capability="tool:issue_refund",
        issuer_public_key=issuer_keys.public_bytes,
        on_decision=decisions.append,
    )
    server.tool()(guarded)

    # MCP builds the schema from the wrapped function's original signature.
    # The bearer token is therefore not an LLM-controlled tool argument.
    tools = asyncio.run(list_tools())
    if isinstance(tools, dict):
        tools = list(tools.values())
    if [tool.name for tool in tools] != ["process_refund"]:
        raise RuntimeError("MCP server did not register process_refund")
    schema = getattr(tools[0], "inputSchema", getattr(tools[0], "input_schema", {}))
    if "token" in schema.get("properties", {}):
        raise RuntimeError("authorization token leaked into the MCP tool schema")

    token = issuer.issue(
        iss="agent:support",
        sub="tool:issue_refund",
        capabilities=["tool:issue_refund"],
    )

    # In production, `validate_oauth_access_token` would call the OAuth
    # resource server/introspection endpoint and return the JCT minted for the
    # validated principal. This local adapter stands in for that provider.
    def validate_oauth_access_token(access_token: str) -> str:
        if access_token != "oauth-access-token":
            raise ValueError("unexpected OAuth access token")
        return token

    request_headers = {"Authorization": "Bearer oauth-access-token"}
    with swarmauth.use_oauth_bearer_token(request_headers, validate=validate_oauth_access_token):
        result = guarded(invoice_id="INV-100", amount_usd=25.0)
        if result != "refunded 25.0 for INV-100":
            raise RuntimeError("guarded MCP invocation returned an unexpected result")

    if decisions[-1].outcome != "allow" or decisions[-1].jti is None:
        raise RuntimeError("MCP invocation did not emit an attributable allow decision")
    print("MCP/OAuth execution-boundary reference: ok")


if __name__ == "__main__":
    main()
