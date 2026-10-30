# Production controls

SwarmAuth authorizes actions at execution. Keep issuer policies and signing
keys outside model-accessible tools. Runtime code attaches credentials; models
must not choose the trust registry, budget rules, or approval records.

## Shared budgets and currencies

`max_amount_usd` remains supported. Its cumulative accounting now adds decimal
representations exactly: `0.1` followed by `0.2` fits a `0.3` ceiling. It does
not perform currency conversion or reinterpret USD as another currency.

For task or agent budgets, use integer minor units with an explicit currency:

```python
import time
import swarmauth

rules = [swarmauth.BudgetRule(
    id="task-42", issuers=("cell:procurement",), currency="GHS",
    max_amount_minor=500_000, expires_at=int(time.time()) + 3600,
    max_calls=20,
)]  # GHS 5,000 total, shared across tokens and allowed issuing cells
tracker = swarmauth.BudgetUsageTracker(rules)
# Across processes, use:
# tracker = swarmauth.RedisBudgetUsageTracker(redis_client, rules)

params = {"budget_id": "task-42", "currency": "GHS", "amount_minor": 12500}
constraints = swarmauth.Constraints(
    max_calls=1, shared_budget="task-42", allowed_params=params,
)
```

Issue these constraints under a trusted `TokenIssuer` policy. A grant with a
`budget_id` pin requires the matching `shared_budget` marker. The guarded
callable accepts the same three parameters; its normal parameter checks bind
the signed budget and amount to the action. Issuer allowlists are checked
against the root issuer even when a worker attenuates the token.

Each successful authorization reserves token, parent, and budget records in
one operation. A rejected reservation changes none. Budgets have their own
expiry and survive token renewal. Give multiple cells the same task budget,
or share an agent budget across multiple tasks. Configure the same immutable
rules on every verifier; changing a budget's id creates a new allowance.
Business cost must be resolved from trusted pricing/order state before minting
and execution, rather than accepted as a model's estimate.

Run `python examples/task_budgets.py` for an executable example.

### Redis and rolling upgrades

Python `RedisBudgetUsageTracker` and Node `RedisUsageTracker` share the same
ledger format and default prefix (`swarmauth:ledger:`). They can enforce the
same tokens and budgets against one Redis database, including Unicode budget
ids. WATCH/MULTI/EXEC reserves all involved keys together. Contention is bounded
and errors fail closed. Redis Cluster is not supported.

Use a dedicated, access-controlled Redis deployment without eviction; select
persistence/replication guarantees appropriate to your actions. Clearing or
losing accounting state can reopen allowances. Never silently fall back to a
process-local tracker after a Redis error.

The existing Python `RedisUsageTracker` uses a separate legacy key layout.
Drain all accepted tokens before switching between layouts or namespaces.
Once on the shared ledger, process restarts retain usage until its expiry.

Existing tokens retain their encoding. Budget-bearing tokens add the optional
`constraints.shared_budget` field. Older SDKs reject it as an unknown constraint;
updated execution guards reject it unless a budget-aware tracker is installed.
Upgrade verifiers before enabling this feature. A child cannot remove or
change its parent's shared budget. The TypeScript reference understands the
wire profile but is not an execution-boundary SDK; use the Node package for
stateful enforcement.

## Asynchronous enforcement

Python `async_guard` / `async_verify_and_check` await asynchronous stores,
trackers, and decision callbacks before execution. A synchronous store can be
used directly if it is fast and local. For synchronous Redis clients, wrap the
usage tracker in `AsyncUsageTracker` to run network work in a thread:

```python
tracker = swarmauth.AsyncUsageTracker(
    swarmauth.RedisBudgetUsageTracker(redis_client, rules)
)

@swarmauth.async_guard("tool:reserve_stock", key_registry=registry, tracker=tracker)
async def reserve_stock(budget_id: str, currency: str, amount_minor: int):
    return await inventory.reserve(budget_id, currency, amount_minor)
```

Synchronous guards reject awaitables from trackers and decision callbacks.
Cancellation or a callback/tool failure may happen after reservation commits:
the allowance stays consumed. Application idempotency is still required.

Node uses native asynchronous Redis clients. The package has no runtime Redis
dependency; pass a connected `redis.createClientPool()` pool:

```js
import { createClientPool } from "redis";
import {
  RedisUsageTracker, asyncGuard, TokenIssuer, Grant, IssuerPolicy, useToken,
} from "swarmauth";

const pool = createClientPool({ url: process.env.REDIS_URL });
pool.on("error", reportInfrastructureFailure);
await pool.connect();
const tracker = new RedisUsageTracker(pool, {
  requireBudget: true,
  rules: [{ id: "task-42", issuers: ["cell:procurement"], currency: "GHS",
    maxAmountMinor: 500_000, expiresAt: Math.floor(Date.now() / 1000) + 3600 }],
});
const issuer = new TokenIssuer(privateKey, { policy: new IssuerPolicy([
  new Grant({ iss: "cell:procurement", sub: "tool:reserve_stock",
    capabilities: ["tool:reserve_stock"], maxCalls: 1,
    pinnedParams: { budget_id: "task-42" } }),
]) });
const params = { budget_id: "task-42", currency: "GHS", amount_minor: 12500 };
const token = issuer.issue({ iss: "cell:procurement", sub: "tool:reserve_stock",
  capabilities: ["tool:reserve_stock"], constraints: {
    max_calls: 1, shared_budget: "task-42", allowed_params: params,
  } });
const reserve = asyncGuard(executeReservation, {
  capability: "tool:reserve_stock", registry, tracker,
});
await useToken(token, () => reserve(params));
await pool.close();
```

`TokenIssuer` always checks the policy before signing and does not accept
caller overrides for timestamps, token ids, or signing keys. Low-level `issue`
remains available for protocol tooling. The npm package includes TypeScript
declarations; `ts/` remains a separate protocol reference, not a second choice
for production Node guards.

## Approval grants

`ApprovalService` turns a trusted approval into short-lived authorization for
an exact resource revision and request digest. Payloads use portable JSON with
safe integers; use minor units for money. Neither approving nor issuing is a
model-callable tool.

```python
service = swarmauth.ApprovalService(swarmauth.RedisApprovalStore(redis_client))
approval = service.approve(
    "distributor-1/order-42", "revision-7", approved_order,
    expires_at=int(time.time()) + 3600,
)
token = service.issue(
    approval.id, issuer=approval_issuer, iss="service:approval",
    sub="tool:submit_purchase_order", capabilities=["tool:submit_purchase_order"],
)

# Load current_order/revision from trusted business storage, then authorize.
claims = service.authorize(
    token, approval_id=approval.id, resource_id="distributor-1/order-42",
    revision=current_revision, payload=current_order,
    audience="tool:submit_purchase_order", capability="tool:submit_purchase_order",
    key_registry=registry, tracker=shared_token_tracker,
)
```

Changed content or revisions require another approval. Approving a newer
revision supersedes the older approval. Call `service.store.invalidate(id)`
when editing/cancelling a resource. The store consumes an approval once across
all tokens and processes: issuing another token cannot replay the approval.

Authorization consumes token usage first, then atomically consumes approval.
If the second step fails, the token remains spent and execution is rejected.
A crash after consumption also requires a fresh approval. Coordinate current
row loading, edit invalidation, and the actual side effect within your business
transaction/locking and idempotency design. The helper does not claim exactly-once
delivery or atomically commit your application's purchase order.

## HTTP and MCP integration

`swarmauth.transport.TokenContextMiddleware` attaches an incoming HTTP bearer
credential to ASGI request context. This supports FastAPI/Starlette applications.
It rejects missing, oversized, and duplicate credentials, but **does not itself
authorize actions**. Wrap endpoints/tool callables with `guard`/`async_guard`.
Mount it only on protected paths; discovery/health routes may need separate
authentication. Map authorization exceptions to sanitized HTTP errors.

For HTTP MCP, use `secure_mcp_http_tool` with the framework's injected Context:

```python
from mcp.server.mcpserver import Context
from swarmauth.transport import secure_mcp_http_tool

async def reserve_stock(value: str, ctx: Context) -> str:
    return await inventory.reserve(value)

server.tool()(secure_mcp_http_tool(
    reserve_stock, capability="tool:reserve_stock", key_registry=registry,
    tracker=async_shared_tracker,
))
```

The wrapper reads **per-message** HTTP headers from the injected Context,
then performs normal authorization. Credentials do not become tool arguments
or get reused from connection initialization. This path targets MCP 2's Context
API. For stdio/local runtimes, use existing `secure_mcp_tool` and `use_token`.
SwarmAuth does not replace MCP's transport/session authentication requirements.

Node exports `tokenContextMiddleware()` for Express. Register it on protected
routes, and use `asyncGuard` inside handlers. Pass explicit business arguments
to guarded tools, rather than forwarding an arbitrary request body containing
an alternate `token` field. Header values are credentials, not trusted agent
identity assertions. Public keys and registries come from server configuration.

## Go verification and HTTP enforcement

See [the Go SDK](../go/README.md). It verifies signatures, delegation, key
rotation/revocation, constraints, and shared protocol vectors without external
dependencies. Use `Authorize` or `HTTPMiddleware` before side effects; `Verify`
alone only validates the credential. The supplied tracker is process-local.
Implement the atomic `UsageTracker` interface for distributed deployments;
shared-budget tokens require an explicitly budget-aware implementation and
are rejected by the default memory tracker.

## Diagnostics and event export

Read credentials from stdin to avoid exposing them in process arguments:

```sh
printf '%s' "$JCT" | python -m swarmauth inspect
printf '%s' "$JCT" | python -m swarmauth verify \
  --public-key-hex "$PUBLIC_KEY_HEX" --audience tool:reserve_stock \
  --capability tool:reserve_stock --params-file actual-params.json
python -m swarmauth policy-check --policy-file issuer-policy.json --request-file request.json
```

`inspect` marks output unverified and omits credentials, embedded parent tokens,
and pinned parameter values. `verify` is an offline diagnostic: it does not
check revocation, reserve usage, or authorize execution. Policy files have one
`grants` array containing the Python `Grant` field names. Policy checks never
sign a token. Keep policy configuration outside model-controlled content.

`JsonlDecisionSink(stream)` from `swarmauth.events` can be passed as
`on_decision`. It emits existing credential-free metadata as JSONL for a log
collector. Stream errors fail closed. Events describe authorization/reservation,
not whether the tool's side effect succeeded.
