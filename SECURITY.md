# Security Policy

SwarmAuth is a security-critical component by design — it is the thing
standing between a compromised LLM's decision and an unauthorized action
actually executing. Please report suspected vulnerabilities responsibly.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a suspected vulnerability.**

Preferred: use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository (Security tab → "Report a vulnerability"). This opens a
private advisory visible only to maintainers until a fix is ready.

If private reporting isn't available on this repository yet, open an issue
asking a maintainer to enable it, without describing the vulnerability
itself, and a maintainer will follow up with a private channel.

Please include, where possible:

- The affected version / commit.
- Whether the issue is in the protocol (SPEC.md — a design flaw in the
  token format or verification algorithm) or in this specific SDK
  implementation (a bug in `swarmauth/`).
- A minimal reproduction: for a token-forging or bypass claim, ideally a
  runnable script (in the spirit of `benchmarks/swarmbench.py`) showing an
  unauthorized action executing despite SwarmAuth being in the loop.
- Impact: what an attacker gains (signature forgery, capability bypass,
  constraint bypass, replay beyond the token's TTL, etc.).

## Scope

In scope:

- `swarmauth/crypto.py`, `swarmauth/token.py`, `swarmauth/middleware.py` —
  signing, verification, capability/constraint enforcement.
- The protocol itself, as specified in [SPEC.md](SPEC.md) — if you believe
  the *design* (not just an implementation) has a flaw (e.g. a way to
  construct a token that satisfies verification without proper
  authorization), that's very much in scope and especially valuable to
  report.
- `benchmarks/swarmbench.py`, if you find it does not accurately represent
  the security property it claims to demonstrate.

Out of scope:

- Vulnerabilities requiring an attacker to already possess a valid issuer
  private key (key custody is a deployment concern, not a protocol one —
  see SPEC.md §8).
- Denial of service against a deployment's own infrastructure (rate limiting
  beyond `constraints.rate_limit_per_min` is a deployment concern).
- Issues in third-party frameworks (LangChain, CrewAI, AutoGen/ag2) that
  swarmauth's adapters wrap but do not implement.

## Response

This is a young, community-maintained project without a formal SLA yet.
Maintainers will acknowledge reports as promptly as possible and prioritize
protocol-level and signature/capability-bypass findings first.
