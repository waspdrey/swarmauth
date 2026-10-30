<div align="center">

# SwarmAuth

### Capability-based authorization for autonomous AI agents

**Secure agent-to-agent delegation and agent-to-tool execution with short-lived, cryptographically signed tokens.**

[![PyPI](https://img.shields.io/pypi/v/swarmauth.svg?style=flat-square)](https://pypi.org/project/swarmauth/)
[![Python](https://img.shields.io/pypi/pyversions/swarmauth.svg?style=flat-square)](https://pypi.org/project/swarmauth/)
[![CI](https://github.com/waspdrey/swarmauth/actions/workflows/ci.yml/badge.svg?style=flat-square)](https://github.com/waspdrey/swarmauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

[Website](https://swarmauth.dev) · [Specification](SPEC.md) · [Security](SECURITY.md) · [Benchmarks](benchmarks/swarmbench.py) · [GitHub](https://github.com/waspdrey/swarmauth)

</div>

---

## Overview

AI agents can plan, delegate, and call tools. But a model's decision to perform an action should not, by itself, authorize that action.

**SwarmAuth moves authorization to the execution boundary.** It issues short-lived, Ed25519-signed tokens describing which capabilities an agent may exercise, which recipient the token targets, and which constraints apply. The receiving tool verifies those claims before executing.

This is particularly important when an agent encounters malicious instructions through messages, documents, retrieved pages, or tool responses. SwarmAuth does **not** detect or eliminate prompt injection. Instead, it helps prevent a compromised agent from exercising capabilities it was never granted.

SwarmAuth provides a capability-token protocol and Python SDK for multi-agent systems. Its design draws on delegated authorization concepts; it should **not** be mistaken for a complete OAuth 2.1 implementation. See the [protocol specification](SPEC.md) for the exact format and security requirements.

## Why SwarmAuth?

| Capability | What it provides |
| --- | --- |
| **Scoped delegation** | Explicit `capabilities`, recipient (`sub`), and optional `constraints` in each token. |
| **Short-lived access** | A maximum token lifetime of **300 seconds**, enforced by verifiers. |
| **Cryptographic verification** | Ed25519 signatures checked before protected execution. |
| **Execution-time enforcement** | The `@guard()` decorator protects Python callables independently of an LLM's instructions. |
| **Multi-issuer trust** | `KeyRegistry` supports multiple trusted issuers and key rotation. |
| **Distributed limits** | `RedisUsageTracker` coordinates usage constraints across verifier processes. |
| **Token revocation** | In-memory and Redis-backed revocation stores support invalidation before expiry. |
| **Framework adapters** | Integration helpers for LangChain, CrewAI, AutoGen, and MCP tools. |
| **Cross-language test vectors** | Byte-exact vectors for independent implementations of the token protocol. |

### Where it fits

Use SwarmAuth wherever an autonomous decision can trigger a consequential action: payment processing, refunds, infrastructure commands, repository merges, deployments, outbound communications, healthcare-record updates, or paid API calls.

It is an **authorization layer**, not an agent framework, prompt-injection classifier, secrets manager, or replacement for application-level validation.

## How it works

```text
Requesting agent
      │
      │ Requests an action with a delegated token
      ▼
Protected tool / receiving agent
      │
      ├── Verify signature and trusted issuer
      ├── Check token lifetime and intended recipient
      ├── Check required capability and constraints
      └── Check revocation / usage limits when configured
      │
      ├── Authorized ──► Execute tool
      └── Rejected   ──► Raise authorization error
```

The tool does not infer permission from a model-generated request. Permission must be represented in a verifiable token. The issuer's authority, token issuance policy, and tool-side enforcement remain critical parts of a secure deployment.

## Installation

```bash
pip install swarmauth
```

For development from source:

```bash
git clone https://github.com/waspdrey/swarmauth.git
cd swarmauth
pip install -e ".[dev,frameworks,redis]"
pytest
```

## Quickstart

Generate a keypair, protect a callable, and issue a scoped token:

```python
import swarmauth

keys = swarmauth.KeyPair.generate()

@swarmauth.guard(
    "tool:process_payout",
    issuer_public_key=keys.public_bytes,
)
def process_payout(destination_account: str, amount_usd: float):
    ...  # Implement your protected tool logic

token = swarmauth.TokenIssuer(keys).issue(
    iss="agent:requester-01",
    sub="tool:process_payout",
    capabilities=["tool:process_payout"],
    ttl_seconds=60,
)
```

The example demonstrates token issuance and guard configuration. **It does not invoke the guarded function.** Consult the SDK API and tests for how to pass the token to a protected call in your installed version. Keep issuer identity and signing-key ownership consistent with your trust policy; generating a signature alone does not establish that an issuer should be trusted.

## Framework integrations

SwarmAuth includes adapters for common agent and tool environments:

| Framework | Adapter |
| --- | --- |
| LangChain | `secure_langchain_tool` |
| CrewAI | `secure_crewai_tool` |
| AutoGen | `secure_autogen_function` |
| Model Context Protocol (MCP) | `secure_mcp_tool` |

See [`swarmauth/middleware.py`](swarmauth/middleware.py) for implementations and [`tests/test_framework_adapters.py`](tests/test_framework_adapters.py) for integration examples. The source describes tests against installed LangChain, `ag2`, and MCP packages.

## Operating at swarm scale

### 1. Multiple issuers and key rotation

Use `KeyRegistry` when tools need to recognize several issuers or accept a replacement key during a controlled rotation.

```python
import swarmauth
from swarmauth.registry import KeyRegistry

registry = KeyRegistry()
registry.register("agent:issuer-a", keys_a.public_bytes)
registry.register("agent:issuer-b", keys_b.public_bytes)

# Allow a new key during the rotation window.
registry.register("agent:issuer-a", new_keys_a.public_bytes, rotate=True)

# Revoke the old key after the transition.
registry.revoke("agent:issuer-a", keys_a.public_bytes)

@swarmauth.guard("tool:process_payout", key_registry=registry)
def process_payout(destination_account: str, amount_usd: float):
    ...
```

`keys_a`, `keys_b`, and `new_keys_a` represent keypairs provisioned by your application. See [SPEC.md](SPEC.md) for issuer and rotation semantics.

### 2. Distributed usage limits

Use Redis to coordinate limits across multiple tool processes:

```python
import redis
import swarmauth
from swarmauth.backends.redis_backend import RedisUsageTracker

tracker = RedisUsageTracker(redis.Redis.from_url("redis://localhost:6379/0"))

@swarmauth.guard(
    "tool:process_payout",
    key_registry=registry,
    tracker=tracker,
)
def process_payout(destination_account: str, amount_usd: float):
    ...
```

The tracker supports constraints such as `max_calls`, `max_amount_usd`, and `rate_limit_per_min`. The configured tracker and constraints determine how those limits are enforced.

### 3. Early revocation

Invalidate a compromised token before its normal expiration:

```python
import swarmauth
from swarmauth.revocation import InMemoryRevocationStore

revocation_store = InMemoryRevocationStore()

@swarmauth.guard(
    "tool:process_payout",
    key_registry=registry,
    revocation_store=revocation_store,
)
def process_payout(destination_account: str, amount_usd: float):
    ...

# After obtaining the compromised token's verified claims:
revocation_store.revoke(claims.jti, expires_at=claims.exp)
```

For multiple processes, use `RedisRevocationStore` from `swarmauth.backends.redis_backend`. The in-memory store is process-local.

These components are optional. Single-issuer integrations can use `issuer_public_key` and the default in-memory usage tracker.

## Security model

SwarmAuth enforces permissions at the receiving execution boundary. A successful prompt injection may influence an agent's requested action, but it cannot by itself create a valid token granting an unissued capability.

**Important boundaries:**

- The verifier must trust the correct issuer keys and check the intended recipient.
- Signing keys and the issuance service must be protected. A compromised authorized issuer can issue powerful tokens.
- A token granting a dangerous capability still permits that capability within its scope; apply least privilege and constraints.
- Authorization does not replace argument validation, business rules, human approval, audit logging, or safe tool implementation.
- Shared revocation and usage tracking require the appropriate distributed backend.

Read the [protocol specification](SPEC.md), [security policy](SECURITY.md), and threat-model discussion in the specification before deploying sensitive workflows.

## SwarmBench: testing the execution boundary

[`benchmarks/swarmbench.py`](benchmarks/swarmbench.py) simulates an inbound customer message containing an instruction to send **$50,000** to an attacker-controlled account. The benchmark assumes the injection succeeds at the model layer and compares what happens when the tool call is unprotected versus capability-guarded.

```bash
python benchmarks/swarmbench.py
```

### Reported benchmark results

| Scenario | Injection modeled as successful | Unauthorized payout in simulation | Outcome |
| --- | --- | --- | --- |
| Unprotected agent loop | Yes | Yes | Tool accepts the unauthorized request. |
| SwarmAuth-protected agent loop | Yes | No | `CapabilityViolationError` blocks execution. |

**Reported mean token verification overhead: 0.12 ms/op** (target: under 1 ms).

These are results reported by the supplied project benchmark, **not independently reproduced measurements or evidence of protection against every attack**. Runtime performance depends on environment and configuration.

In the protected case, the requesting agent holds a token for `tool:draft_payout`, not `tool:process_payout`. The verifier rejects the attempted escalation before the payout handler runs.

## Protocol and interoperability

The [specification](SPEC.md) defines the token claims, canonicalization rules, signature and verification behavior, and protocol security requirements.

The [`spec/test-vectors/`](spec/test-vectors/) directory contains signed token vectors and expected outcomes, including expiration edge cases. Use these to test compatibility when implementing the protocol in another language.

## Repository structure

```text
.
├── SPEC.md                    # Protocol specification
├── README.md                  # Project overview
├── CONTRIBUTING.md            # Contribution guidance
├── SECURITY.md                # Security policy
├── tox.ini                    # Local CI environments
├── .github/workflows/ci.yml  # CI pipeline
├── scripts/                   # Audits, vectors, release checks
├── spec/test-vectors/         # Interoperability fixtures
├── swarmauth/
│   ├── crypto.py              # Ed25519 primitives
│   ├── token.py               # Token issuance and verification
│   ├── registry.py            # Issuer trust and key rotation
│   ├── middleware.py          # Guard and framework adapters
│   ├── revocation.py          # Revocation interfaces and memory store
│   ├── backends/redis_backend.py
│   ├── exceptions.py
│   └── py.typed
├── benchmarks/swarmbench.py
└── tests/                     # Unit, integration, and protocol tests
```

## Development and testing

```bash
# Run tests
pytest

# Run the benchmark
python benchmarks/swarmbench.py

# Run available tox environments
tox -e lint
tox -e py312
tox -e frameworks
```

The project also includes a `redis-live` tox environment and release-artifact verification tooling. Review [`tox.ini`](tox.ini) and the [CI workflow](.github/workflows/ci.yml) for environment requirements and checks.

## Design principles

1. **Least privilege by default.** Grant only the capabilities and limits required for a specific task.
2. **Verification at execution.** Do not rely on the model to decide whether it is authorized.
3. **Short-lived delegation.** Limit the window in which issued credentials can be exercised.
4. **Explicit failure.** Surface named errors such as `TokenExpiredError`, `CapabilityViolationError`, and `ConstraintViolationError`.
5. **Minimal required infrastructure.** Token verification does not require a central network service; distributed controls are opt-in.
6. **Interoperability.** Keep the token format and verification behavior testable across implementations.

## Project status

**MVP / RFC — 0.x series.** The supplied project description treats the token format, claims schema, and verification algorithm as stable within 0.x, while framework adapters continue to evolve.

The described SDK includes multi-issuer key rotation, token revocation, and distributed usage tracking. Check the current package and repository before relying on a particular feature or API in production.

Contributions and issue reports are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

SwarmAuth is distributed under the [MIT License](LICENSE).

---

<div align="center">

**Authorization should be verified, not inferred.**

[Website](https://swarmauth.dev) · [GitHub](https://github.com/waspdrey/swarmauth) · [X / Twitter](https://twitter.com/swarmauth)

</div>
