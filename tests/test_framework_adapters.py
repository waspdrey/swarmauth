"""Integration tests for the framework adapters against REAL installed
frameworks, not mocks -- these exercise langchain-core's actual `StructuredTool`
/ `BaseTool` classes, ag2's actual `@tool` decorator, and a real
`mcp.server.mcpserver.MCPServer`.

CrewAI is deliberately not installed here: its dependency chain (chromadb,
onnxruntime, embedchain, ...) is heavy enough that pulling it in for CI would
slow every run substantially for a single adapter. `secure_crewai_tool` is a
direct alias of `secure_langchain_tool` because CrewAI's `Tool`/`BaseTool`
classes expose the same `.func` / `._run` shape exercised below by the
LangChain tests -- see `test_secure_crewai_tool_is_langchain_tool_alias`.

These tests require the `dev` extras: `pip install -e ".[dev]"`.
"""
from __future__ import annotations

import asyncio

import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError
from swarmauth.middleware import (
    TokenIssuer,
    secure_autogen_function,
    secure_crewai_tool,
    secure_langchain_tool,
    secure_mcp_tool,
)
from swarmauth.token import Constraints

langchain_core = pytest.importorskip("langchain_core", reason="pip install -e '.[dev]' to run framework adapter tests")
ag2 = pytest.importorskip("ag2", reason="pip install -e '.[dev]' to run framework adapter tests")
mcp = pytest.importorskip("mcp", reason="pip install -e '.[dev]' to run framework adapter tests")

from langchain_core.tools import BaseTool, StructuredTool  # noqa: E402
from mcp.server.mcpserver import MCPServer  # noqa: E402


# ---------------------------------------------------------------------------
# LangChain: function-based tools (StructuredTool, the `.func` branch)
# ---------------------------------------------------------------------------


def _make_payout_structured_tool() -> StructuredTool:
    def process_payout(destination_account: str, amount_usd: float) -> str:
        return f"sent {amount_usd} to {destination_account}"

    return StructuredTool.from_function(
        func=process_payout, name="process_payout", description="Pay out funds to an account."
    )


def test_langchain_structured_tool_invoke_blocked_without_token():
    kp = KeyPair.generate()
    tool = secure_langchain_tool(
        _make_payout_structured_tool(), capability="tool:process_payout", issuer_public_key=kp.public_bytes
    )
    # Real LangChain call path: .invoke() goes through the tool's own schema
    # validation and then calls the (now-wrapped) underlying func. No token is
    # in the LLM-visible schema, so the wrapper's "no token supplied" branch
    # fires -- exactly the behavior a compromised LLM planning a call, with no
    # legitimate token in hand, should hit.
    with pytest.raises(CapabilityViolationError):
        tool.invoke({"destination_account": "ATTACKER-ACCT-9999", "amount_usd": 50000.0})


def test_langchain_structured_tool_func_executes_with_valid_token():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    tool = secure_langchain_tool(
        _make_payout_structured_tool(), capability="tool:process_payout", issuer_public_key=kp.public_bytes
    )
    token = issuer.issue(iss="agent:a", sub="tool:process_payout", capabilities=["tool:process_payout"])

    # The token is never part of the LLM-facing schema (see module docstring
    # of swarmauth.middleware): the calling agent's runtime -- not the model --
    # supplies it directly to the wrapped callable.
    result = tool.func(destination_account="acct_1", amount_usd=5.0, token=token)
    assert result == "sent 5.0 to acct_1"


def test_langchain_structured_tool_constraint_blocks_wrong_destination():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    tool = secure_langchain_tool(
        _make_payout_structured_tool(), capability="tool:process_payout", issuer_public_key=kp.public_bytes
    )
    token = issuer.issue(
        iss="agent:a",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=Constraints(allowed_params={"destination_account": "acct_1"}),
    )

    with pytest.raises(ConstraintViolationError):
        tool.func(destination_account="ATTACKER-ACCT-9999", amount_usd=5.0, token=token)


# ---------------------------------------------------------------------------
# LangChain: class-based tools (BaseTool subclass, the `._run` branch)
# ---------------------------------------------------------------------------


class ReadInvoiceTool(BaseTool):
    name: str = "read_invoice"
    description: str = "Read an invoice by ID."

    def _run(self, invoice_id: str) -> str:
        return f"invoice {invoice_id}: $100 due"


def test_langchain_base_tool_run_branch_blocked_without_token():
    kp = KeyPair.generate()
    tool = secure_langchain_tool(ReadInvoiceTool(), capability="tool:read_invoice", issuer_public_key=kp.public_bytes)
    with pytest.raises(CapabilityViolationError):
        tool._run(invoice_id="INV-1")


def test_langchain_base_tool_run_branch_allowed_with_token():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    tool = secure_langchain_tool(ReadInvoiceTool(), capability="tool:read_invoice", issuer_public_key=kp.public_bytes)
    token = issuer.issue(iss="agent:a", sub="tool:read_invoice", capabilities=["tool:read_invoice"])
    assert tool._run(invoice_id="INV-1", token=token) == "invoice INV-1: $100 due"


# ---------------------------------------------------------------------------
# CrewAI alias
# ---------------------------------------------------------------------------


def test_secure_crewai_tool_behaves_like_secure_langchain_tool():
    # CrewAI's own Tool/BaseTool classes expose the same .func/._run shape
    # exercised above; secure_crewai_tool delegates straight to
    # secure_langchain_tool, so it gets identical enforcement against the
    # same real BaseTool class used in the LangChain tests.
    kp = KeyPair.generate()
    tool = secure_crewai_tool(ReadInvoiceTool(), capability="tool:read_invoice", issuer_public_key=kp.public_bytes)
    with pytest.raises(CapabilityViolationError):
        tool._run(invoice_id="INV-1")


# ---------------------------------------------------------------------------
# AutoGen / ag2: decorator-based tools
# ---------------------------------------------------------------------------


def test_secure_autogen_function_composes_with_real_ag2_tool_decorator():
    kp = KeyPair.generate()

    def process_payout(destination_account: str, amount_usd: float) -> str:
        return f"sent {amount_usd} to {destination_account}"

    guarded = secure_autogen_function(process_payout, capability="tool:process_payout", issuer_public_key=kp.public_bytes)

    # Real ag2 (the actively-maintained AutoGen fork) tool decorator: proves
    # the wrapped callable is still introspectable enough for ag2's schema
    # generation to succeed, i.e. wrapping doesn't break real registration.
    function_tool = ag2.tool(guarded)
    assert function_tool.name == "process_payout"


def test_secure_autogen_function_blocks_without_token():
    kp = KeyPair.generate()

    def process_payout(destination_account: str, amount_usd: float) -> str:
        return f"sent {amount_usd} to {destination_account}"

    guarded = secure_autogen_function(process_payout, capability="tool:process_payout", issuer_public_key=kp.public_bytes)
    with pytest.raises(CapabilityViolationError):
        guarded(destination_account="ATTACKER-ACCT-9999", amount_usd=50000.0)


# ---------------------------------------------------------------------------
# Model Context Protocol (MCP): decorator-based tools on a real server
# ---------------------------------------------------------------------------


def test_secure_mcp_tool_schema_omits_token_and_registers_under_real_name():
    kp = KeyPair.generate()
    server = MCPServer("swarmauth-test-server")

    def process_payout(destination_account: str, amount_usd: float) -> str:
        return f"sent {amount_usd} to {destination_account}"

    guarded = secure_mcp_tool(process_payout, capability="tool:process_payout", issuer_public_key=kp.public_bytes)
    server.tool()(guarded)

    tools = asyncio.run(server.list_tools())
    assert [t.name for t in tools] == ["process_payout"]
    # The schema the model actually sees must NOT include `token` -- proving
    # the security-critical claim in swarmauth/middleware.py's adapter note:
    # schema generation follows __wrapped__ straight past the guard's kwarg.
    assert set(tools[0].input_schema.get("properties", {})) == {"destination_account", "amount_usd"}


def test_secure_mcp_tool_blocks_without_token_even_though_registered():
    kp = KeyPair.generate()
    server = MCPServer("swarmauth-test-server")

    def process_payout(destination_account: str, amount_usd: float) -> str:
        return f"sent {amount_usd} to {destination_account}"

    guarded = secure_mcp_tool(process_payout, capability="tool:process_payout", issuer_public_key=kp.public_bytes)
    server.tool()(guarded)

    with pytest.raises(CapabilityViolationError):
        guarded(destination_account="ATTACKER-ACCT-9999", amount_usd=50000.0)


def test_secure_mcp_tool_executes_with_valid_token():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    server = MCPServer("swarmauth-test-server")

    def process_payout(destination_account: str, amount_usd: float) -> str:
        return f"sent {amount_usd} to {destination_account}"

    guarded = secure_mcp_tool(process_payout, capability="tool:process_payout", issuer_public_key=kp.public_bytes)
    server.tool()(guarded)

    token = issuer.issue(iss="agent:a", sub="tool:process_payout", capabilities=["tool:process_payout"])
    assert guarded(destination_account="acct_1", amount_usd=5.0, token=token) == "sent 5.0 to acct_1"
