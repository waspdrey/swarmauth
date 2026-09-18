# SwarmAuth

**The zero-trust authorization standard for multi-agent systems.**

SwarmAuth is OAuth 2.1 for autonomous AI swarms: cryptographically signed,
short-lived (≤300s), capability-scoped delegation tokens for agent-to-agent
and agent-to-tool calls. It's built on one assumption you should already
hold — your LLM layer *will* be compromised by prompt injection — and asks a
different question: when that happens, does the execution boundary stop the
damage, or does it just trust whatever the model decided?

Today, most multi-agent stacks pass raw API keys or unscoped bearer tokens
between agents. Read the full threat model and protocol details in
[SPEC.md](SPEC.md).

## Why

- **Prompt injection is not a solved problem, and won't be soon.** SwarmAuth
  doesn't try to detect or prevent it — it makes the LLM's decision
  irrelevant at the point of execution.
- **Capability tokens, not credentials.** A token names exactly what it
  authorizes (`caps`), against whom (`sub`), and under what limits
  (`constraints`: rate limits, call caps, budget caps, parameter
  allowlists) — never a raw, reusable key.
- **Tokens expire in seconds.** Max TTL is 300 seconds, enforced by every
  verifier regardless of what an issuer tries to claim.
- **Zero exotic dependencies.** Ed25519 via `cryptography`, schema via
  `pydantic`. That's the whole dependency tree.
- **Sub-millisecond verification.** See benchmark results below.

## Quickstart

```python
from swarmauth import KeyPair
from swarmauth.middleware import TokenIssuer, require_capability

finance_keys = KeyPair.generate()

@require_capability("tool:process_payout", issuer_public_key=finance_keys.public_bytes)
def process_payout(destination_account: str, amount_usd: float):
    ...  # your real tool logic — only ever reached with a verified, in-scope token
```

Issuing the token an upstream agent presents is one line:

```python
token = TokenIssuer(finance_keys).issue(
    iss="agent:sales-agent-01", sub="tool:process_payout",
    caps=["tool:draft_payout"], ttl_seconds=60,
)
```

That's the entire integration surface: decorate the tool, issue the token.
Framework adapters for LangChain, CrewAI, and AutoGen tools are one call
each — see [`swarmauth/middleware.py`](swarmauth/middleware.py)
(`secure_langchain_tool`, `secure_crewai_tool`, `secure_autogen_function`).

## Install

```bash
pip install -e .
# or, without an editable install:
pip install cryptography pydantic
```

(Not yet published to PyPI — this is the MVP/open-source launch. `pip
install -e .` from a clone works today.)

## Architecture

```mermaid
sequenceDiagram
    participant A as Agent A (Sales Agent)
    participant I as SwarmAuth Token Issuer
    participant B as Agent B / Tool (Finance Agent)

    A->>I: Request capability token (iss=A, sub=B, caps=[...], constraints, ttl<=300s)
    I->>I: Evaluate policy — is A allowed to request these caps against B?
    I-->>A: Signed Capability Token (SACT)
    A->>B: Tool call, with SACT attached
    B->>B: Verify Ed25519 signature, exp/iat window, audience, capability, constraints
    alt Valid & in-scope
        B->>B: Execute tool; record usage against jti
        B-->>A: Result
    else Invalid, expired, wrong audience, missing capability, or over-limit
        B-->>A: Reject (CapabilityViolationError / ConstraintViolationError / ...)
    end
```

Full claims schema, canonicalization rules, and the complete verification
algorithm are in [SPEC.md](SPEC.md).

## SwarmBench: does this actually stop anything?

[`benchmarks/swarmbench.py`](benchmarks/swarmbench.py) runs a runnable
simulation of a Sales Agent that delegates to a Finance Agent's
`process_payout` tool, with a prompt injection embedded in inbound customer
email instructing the Sales Agent to trigger a $50,000 payout to an
attacker-controlled account. The injection is modeled as **succeeding** at
the LLM layer in both test cases — SwarmBench isn't testing whether models
can be fooled (they can); it's testing what happens next.

```bash
python benchmarks/swarmbench.py
```

### Results (from an actual run on this machine)

| Scenario | Injection succeeds at LLM layer | Unauthorized payout executed | Blocked at execution boundary |
|---|---|---|---|
| **Unprotected** agent loop | ✅ Yes | ❌ **Yes — $50,000 sent** | — |
| **SwarmAuth-protected** agent loop | ✅ Yes | ✅ **No** | ✅ Yes (`CapabilityViolationError`) |

| Metric | Value |
|---|---|
| Mean token verification overhead | **0.12 ms/op** (target: <1ms) |

In the unprotected loop, the Finance Agent's tool trusts whatever arguments
it's called with — the injection walks straight through. In the protected
loop, the token the Sales Agent actually holds only grants
`tool:draft_payout` under a policy-set budget; it does not, and cannot,
grant `tool:process_payout` no matter what the compromised LLM decided to
call — so the execution boundary rejects it before the ledger is touched.

## Repository layout

```
swarmauth/
├── SPEC.md                   # protocol specification
├── README.md
├── swarmauth/
│   ├── __init__.py
│   ├── crypto.py              # Ed25519 keypairs, signing, verification
│   ├── token.py                # CapabilityToken: issue / parse / verify
│   ├── middleware.py            # decorators + LangChain/CrewAI/AutoGen adapters
│   └── exceptions.py
├── benchmarks/
│   └── swarmbench.py           # runnable unprotected-vs-protected simulation
└── tests/
    ├── test_token.py
    └── test_middleware.py
```

## Design principles

- No cryptographic dependencies beyond `cryptography`; no schema/validation
  dependencies beyond `pydantic`.
- Strict typing, explicit exception hierarchy (`TokenExpiredError`,
  `CapabilityViolationError`, `ConstraintViolationError`, ...) — callers
  decide how to handle each failure mode, nothing fails silently.
- Tokens are data, not infrastructure: no required network call, no
  mandatory central service. Self-issuance and centralized-issuer
  deployments use the exact same token format and verification code.

## Status

MVP / RFC. The token format, claims schema, and verification algorithm are
considered stable for `0.1.x`; expect the framework adapters and
distributed usage-tracking story (see [SPEC.md §8](SPEC.md#8-security-considerations))
to evolve based on real integration feedback. Issues and PRs welcome.

## License

MIT — see [LICENSE](LICENSE).
