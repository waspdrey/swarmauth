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
    except ImportError as exc:
        raise SystemExit("Install the optional MCP dependency with: pip install -e '.[frameworks]'") from exc

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
    server = MCPServer("swarmauth-oauth-reference")
    server.tool()(guarded)

    # MCP builds the schema from the wrapped function's original signature.
    # The bearer token is therefore not an LLM-controlled tool argument.
    tools = asyncio.run(server.list_tools())
    assert [tool.name for tool in tools] == ["process_refund"]
    assert "token" not in tools[0].input_schema.get("properties", {})

    token = issuer.issue(
        iss="agent:support",
        sub="tool:issue_refund",
        capabilities=["tool:issue_refund"],
    )

    # In production, `validate_oauth_access_token` would call the OAuth
    # resource server/introspection endpoint and return the JCT minted for the
    # validated principal. This local adapter stands in for that provider.
    def validate_oauth_access_token(access_token: str) -> str:
        assert access_token == "oauth-access-token"
        return token

    request_headers = {"Authorization": "Bearer oauth-access-token"}
    with swarmauth.use_oauth_bearer_token(request_headers, validate=validate_oauth_access_token):
        assert guarded(invoice_id="INV-100", amount_usd=25.0) == "refunded 25.0 for INV-100"

    assert decisions[-1].outcome == "allow"
    assert decisions[-1].jti is not None
    print("MCP/OAuth execution-boundary reference: ok")


if __name__ == "__main__":
    main()
