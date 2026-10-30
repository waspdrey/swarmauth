"""Regressions for execution bypasses, cross-token budgets, and approvals."""
from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from swarmauth import (
    ApprovalService,
    AsyncUsageTracker,
    BudgetRule,
    BudgetUsageTracker,
    CapabilityToken,
    CapabilityViolationError,
    Constraints,
    ConstraintViolationError,
    Grant,
    InMemoryApprovalStore,
    IssuerPolicy,
    KeyPair,
    PolicyViolationError,
    RedisApprovalStore,
    RedisBudgetUsageTracker,
    TokenIssuer,
    UsageTracker,
    async_guard,
    async_verify_and_check,
    guard,
    use_token,
)
from swarmauth.middleware import secure_langchain_tool, verify_and_check


def minted(keys, constraints=None, iss="issuer"):
    return CapabilityToken.issue(issuer_keypair=keys, iss=iss, sub="tool:x", capabilities=["tool:x"],
                                 constraints=constraints, ttl_seconds=30)


def test_inherited_async_langchain_handler_is_guarded_and_default_charges_once():
    pytest.importorskip("langchain_core")
    from langchain_core.tools import BaseTool

    class Parent(BaseTool):
        name: str = "echo"
        description: str = "Echo"

        def _run(self, value: str) -> str:
            return value

        async def _arun(self, value: str) -> str:
            return value

    class Child(Parent):
        pass

    class DefaultAsync(BaseTool):
        name: str = "default"
        description: str = "Default async dispatch"

        def _run(self, value: str) -> str:
            return value

    keys = KeyPair.generate()

    async def run():
        for cls in (Child, DefaultAsync):
            tool = secure_langchain_tool(cls(), capability="tool:x", issuer_public_key=keys.public_bytes,
                                         tracker=UsageTracker())
            with pytest.raises(CapabilityViolationError):
                await tool.ainvoke({"value": "blocked"})
            with use_token(minted(keys, Constraints(max_calls=1))):
                assert await tool.ainvoke({"value": "allowed"}) == "allowed"
                with pytest.raises(ConstraintViolationError):
                    await tool.ainvoke({"value": "replay"})
    asyncio.run(run())


def test_sync_guard_rejects_async_tracker_and_callback_before_execution():
    keys = KeyPair.generate()

    class Tracker:
        async def check_and_record(self, claims, *, amount=0):
            pytest.fail("Coroutine must be rejected, not silently ignored")

    async def callback(event):
        pytest.fail("Coroutine must be rejected, not silently ignored")

    for options in ({"tracker": Tracker()}, {"tracker": UsageTracker(), "on_decision": callback}):
        @guard("tool:x", issuer_public_key=keys.public_bytes, **options)
        def tool():
            pytest.fail("Unsupported async authorization must stop execution")
        with pytest.raises(TypeError, match="async"):
            tool(token=minted(keys, Constraints(max_calls=1)))


def test_structured_tool_custom_entrypoints_cannot_ignore_guarded_func():
    pytest.importorskip("langchain_core")
    from langchain_core.tools import StructuredTool

    class Custom(StructuredTool):
        def _run(self, value: str) -> str:
            return value

        async def _arun(self, value: str) -> str:
            return value

    class Inherited(Custom):
        pass

    def value_tool(value: str) -> str:
        """Echo."""
        return value

    keys = KeyPair.generate()
    tool = Inherited.from_function(value_tool)
    secure_langchain_tool(tool, capability="tool:x", issuer_public_key=keys.public_bytes, tracker=UsageTracker())
    with pytest.raises(CapabilityViolationError):
        tool.invoke({"value": "blocked"})

    async def run():
        with pytest.raises(CapabilityViolationError):
            await tool.ainvoke({"value": "blocked"})
        with use_token(minted(keys, Constraints(max_calls=1))):
            assert await tool.ainvoke({"value": "allowed"}) == "allowed"
    asyncio.run(run())


def test_async_guard_awaits_reservation_and_callback_and_fails_closed():
    keys = KeyPair.generate()
    sequence = []

    class Tracker:
        async def check_and_record(self, claims, *, amount=0):
            await asyncio.sleep(0)
            sequence.append("reserved")

    async def callback(event):
        await asyncio.sleep(0)
        sequence.append(event.decision)

    @async_guard("tool:x", issuer_public_key=keys.public_bytes, tracker=Tracker(), on_decision=callback)
    async def tool():
        sequence.append("executed")

    asyncio.run(tool(token=minted(keys, Constraints(max_calls=1))))
    assert sequence == ["reserved", "allowed", "executed"]

    class BrokenTracker:
        async def check_and_record(self, claims, *, amount=0):
            raise ConnectionError("Redis unavailable")

    with pytest.raises(ConnectionError):
        asyncio.run(async_verify_and_check(minted(keys, Constraints(max_calls=1)),
                                          issuer_public_key=keys.public_bytes, tracker=BrokenTracker()))


@pytest.fixture(params=["memory", "redis"])
def ledger(request):
    rules = [BudgetRule("task-42", ("issuer",), "GHS", 100, int(time.time()) + 3600)]
    if request.param == "memory":
        return BudgetUsageTracker(rules)
    import fakeredis
    return RedisBudgetUsageTracker(fakeredis.FakeRedis(), rules)


def budget_token(keys, amount, **pins):
    return minted(keys, Constraints(max_calls=1, shared_budget="task-42", allowed_params={
        "budget_id": "task-42", "currency": "GHS", "amount_minor": amount, **pins,
    }))


def charge(token, keys, ledger, **params):
    return verify_and_check(token, issuer_public_key=keys.public_bytes, audience="tool:x",
                            required_capability="tool:x", tracker=ledger,
                            params={"budget_id": "task-42", "currency": "GHS", **params})


def test_fresh_tokens_share_currency_budget_and_rejections_do_not_charge(ledger):
    keys = KeyPair.generate()
    charge(budget_token(keys, 60), keys, ledger, amount_minor=60)
    rejected = budget_token(keys, 50)
    with pytest.raises(ConstraintViolationError):
        charge(rejected, keys, ledger, amount_minor=50)
    charge(budget_token(keys, 40), keys, ledger, amount_minor=40)
    with pytest.raises(ConstraintViolationError):
        charge(budget_token(keys, 1), keys, ledger, amount_minor=1)


def test_concurrent_fresh_tokens_cannot_overspend_shared_budget(ledger):
    keys = KeyPair.generate()
    tokens = [budget_token(keys, 10) for _ in range(20)]

    def call(token):
        try:
            charge(token, keys, ledger, amount_minor=10)
            return True
        except ConstraintViolationError:
            return False
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert sum(executor.map(call, tokens)) == 10


def test_budget_currency_issuer_and_actual_amount_are_bound(ledger):
    keys = KeyPair.generate()
    for token, params in [
        (budget_token(keys, 10), {"amount_minor": 1}),
        (budget_token(keys, 10, currency="USD"), {"amount_minor": 10, "currency": "USD"}),
        (minted(keys, Constraints(shared_budget="task-42", allowed_params={
            "budget_id": "task-42", "currency": "GHS", "amount_minor": 10}),
                iss="other"), {"amount_minor": 10}),
    ]:
        with pytest.raises(ConstraintViolationError):
            charge(token, keys, ledger, **params)


def test_budget_survives_new_redis_tracker_instance():
    import fakeredis
    client = fakeredis.FakeRedis()
    rule = BudgetRule("task-42", ("issuer",), "GHS", 100, int(time.time()) + 3600)
    keys = KeyPair.generate()
    charge(budget_token(keys, 100), keys, RedisBudgetUsageTracker(client, [rule]), amount_minor=100)
    with pytest.raises(ConstraintViolationError):
        charge(budget_token(keys, 1), keys, RedisBudgetUsageTracker(client, [rule]), amount_minor=1)


@pytest.mark.parametrize("backend", ["memory", "redis", "ledger"])
def test_decimal_usd_sums_accept_exact_boundary_and_reject_excess(backend):
    import fakeredis

    from swarmauth.backends.redis_backend import RedisUsageTracker
    tracker = {"memory": UsageTracker(), "redis": RedisUsageTracker(fakeredis.FakeRedis()),
               "ledger": RedisBudgetUsageTracker(fakeredis.FakeRedis(), [], require_budget=False)}[backend]
    keys = KeyPair.generate()
    token = minted(keys, Constraints(max_amount_usd=0.3))
    for amount in (0.1, 0.2):
        verify_and_check(token, issuer_public_key=keys.public_bytes, tracker=tracker, amount=amount)
    with pytest.raises(ConstraintViolationError):
        verify_and_check(token, issuer_public_key=keys.public_bytes, tracker=tracker, amount=1e-12)


@pytest.mark.parametrize("backend", ["memory", "redis"])
def test_approvals_bind_revision_content_and_are_single_use_across_fresh_tokens(backend):
    import fakeredis
    store = InMemoryApprovalStore() if backend == "memory" else RedisApprovalStore(fakeredis.FakeRedis())
    service = ApprovalService(store)
    keys = KeyPair.generate()
    issuer = TokenIssuer(keys, IssuerPolicy([Grant("approval", "tool:x", ("tool:x",), max_calls=1)]))
    payload = {"currency": "GHS", "amount_minor": 100, "items": ["medicine"]}
    approval = service.approve("order-42", "v1", payload, expires_at=int(time.time()) + 3600)
    tokens = [service.issue(approval.id, issuer=issuer, iss="approval", sub="tool:x", capabilities=["tool:x"])
              for _ in range(2)]
    options = dict(approval_id=approval.id, resource_id="order-42", revision="v1", payload=payload,
                   audience="tool:x", capability="tool:x", tracker=UsageTracker(), issuer_public_key=keys.public_bytes)
    with pytest.raises(PolicyViolationError, match="changed"):
        service.authorize(tokens[0], **{**options, "payload": {**payload, "amount_minor": 101}})
    service.authorize(tokens[0], **options)
    with pytest.raises(PolicyViolationError):
        service.authorize(tokens[1], **options)

    newer = service.approve("order-42", "v2", payload, expires_at=int(time.time()) + 3600)
    newer_token = service.issue(newer.id, issuer=issuer, iss="approval", sub="tool:x", capabilities=["tool:x"])
    store.invalidate("order-42")
    with pytest.raises(PolicyViolationError):
        service.authorize(newer_token, **{**options, "approval_id": newer.id, "revision": "v2"})


def test_asgi_token_context_isolated_across_concurrent_requests():
    pytest.importorskip("starlette")
    pytest.importorskip("httpx")
    from httpx import ASGITransport, AsyncClient
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from swarmauth.transport import TokenContextMiddleware

    keys = KeyPair.generate()

    @async_guard("tool:x", issuer_public_key=keys.public_bytes)
    async def tool(value):
        await asyncio.sleep(0)
        return value

    async def endpoint(request):
        try:
            return JSONResponse({"value": await tool(request.path_params["value"])})
        except ConstraintViolationError:
            return JSONResponse({"error": "denied"}, status_code=403)
    app = TokenContextMiddleware(Starlette(routes=[Route("/{value}", endpoint)]))

    async def run():
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            async def call(value):
                token = minted(keys, Constraints(allowed_params={"value": value}))
                return await client.get("/" + value, headers={"Authorization": "Bearer " + token})
            results = await asyncio.gather(call("first"), call("second"))
            assert [result.json()["value"] for result in results] == ["first", "second"]
            assert (await client.get("/missing")).status_code == 401
            duplicate = [("authorization", "Bearer a"), ("authorization", "Bearer b")]
            assert (await client.get("/duplicate", headers=duplicate)).status_code == 401
    asyncio.run(run())


def test_thread_backed_async_tracker_reserves_before_return(ledger):
    keys = KeyPair.generate()
    token = budget_token(keys, 100)
    options = dict(issuer_public_key=keys.public_bytes, tracker=AsyncUsageTracker(ledger),
                   params={"budget_id": "task-42", "currency": "GHS", "amount_minor": 100})
    asyncio.run(async_verify_and_check(token, **options))
    with pytest.raises(ConstraintViolationError):
        asyncio.run(async_verify_and_check(token, **options))


def test_budget_profile_requires_aware_tracker_and_cannot_be_removed_in_delegation():
    from swarmauth import DelegationError
    from swarmauth.registry import KeyRegistry
    keys, worker = KeyPair.generate(), KeyPair.generate()
    params = {"budget_id": "task-42", "currency": "GHS", "amount_minor": 10}
    constraints = Constraints(shared_budget="task-42", allowed_params=params)
    token = minted(keys, constraints)
    for tracker in (None, UsageTracker()):
        with pytest.raises(ConstraintViolationError, match="budget-aware"):
            verify_and_check(token, issuer_public_key=keys.public_bytes, params=params, tracker=tracker)
    parent = CapabilityToken.issue(issuer_keypair=keys, iss="issuer", sub="tool:x", capabilities=["tool:x"],
                                   constraints=constraints, dlg="worker", ttl_seconds=30)
    with pytest.raises(DelegationError, match="shared budget"):
        CapabilityToken.attenuate(issuer_keypair=worker, parent=parent, iss="worker", capabilities=["tool:x"],
                                  constraints=Constraints(allowed_params=params), ttl_seconds=10)
    child = CapabilityToken.attenuate(issuer_keypair=worker, parent=parent, iss="worker", capabilities=["tool:x"],
                                      constraints=constraints, ttl_seconds=10)
    registry = KeyRegistry()
    registry.register("issuer", keys.public_bytes)
    registry.register_holder("worker", worker.public_bytes)
    budget = BudgetRule("task-42", ("issuer",), "GHS", 10, int(time.time()) + 3600)
    tracker = BudgetUsageTracker([budget])
    verify_and_check(child, key_registry=registry, tracker=tracker, params=params)
    with pytest.raises(ConstraintViolationError):
        verify_and_check(child, key_registry=registry, tracker=tracker, params=params)


def test_real_mcp_dispatch_uses_per_message_http_headers():
    pytest.importorskip("mcp")
    pytest.importorskip("starlette")
    from types import SimpleNamespace

    from mcp.server.mcpserver import Context, MCPServer
    from mcp.server.mcpserver.exceptions import UnexpectedToolError
    from starlette.datastructures import Headers

    from swarmauth.transport import secure_mcp_http_tool

    keys = KeyPair.generate()
    calls = []
    server = MCPServer("swarmauth-http")

    # Resolve Context from the module globals for framework annotation parsing.
    globals()["Context"] = Context

    async def execute(value: str, ctx: Context) -> str:
        calls.append(value)
        return value

    server.tool()(secure_mcp_http_tool(execute, capability="tool:x", issuer_public_key=keys.public_bytes))

    def context(credential):
        headers = Headers({"authorization": "Bearer " + credential}) if credential else Headers()
        return Context(mcp_server=server, request_context=SimpleNamespace(request=SimpleNamespace(headers=headers)))

    async def run():
        tools = await server.list_tools()
        assert set(tools[0].input_schema["properties"]) == {"value"}
        good = minted(keys, Constraints(allowed_params={"value": "allowed"}))
        await server.call_tool("execute", {"value": "allowed"}, context=context(good))
        assert calls == ["allowed"]
        for credential, value in ((None, "allowed"), (good, "wrong")):
            with pytest.raises(UnexpectedToolError):
                await server.call_tool("execute", {"value": value}, context=context(credential))
            assert calls == ["allowed"]
    asyncio.run(run())
