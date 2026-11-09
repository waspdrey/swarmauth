# SwarmAuth threat model

## Security objective

Stop an agent, model, prompt injection, or compromised tool caller from causing
an execution boundary to perform an action outside the authority explicitly
issued for that action.

## Trust boundaries

1. **Issuer process** — holds private signing material and issuer policy.
2. **Agent runtime** — may be compromised by prompt injection; it must not be
   trusted to decide its own authority or supply a token through the model
   schema.
3. **Transport** — may carry or replay a token; it is not trusted for policy.
4. **Tool/execution boundary** — verifies the token and enforces capability,
   audience, parameter, time, and stateful constraints before side effects.
5. **Control plane** — stores public metadata, trust state, revocations, and
   decision evidence; it never stores private keys or bearer tokens.

## In scope

- Forged or tampered JCTs.
- Header `kid` mismatches and issuer key confusion.
- Expired, not-yet-valid, replayed, or revoked tokens.
- Capability widening, audience retargeting, and delegation-chain abuse.
- Parameter, call-count, rate, and budget bypasses.
- Prompt injection that causes an agent to request an unauthorized tool call.
- Missing distributed usage state for a token that declares stateful limits.
- Accidental exposure of tokens through model-visible tool schemas.

## Out of scope

- Compromise of the issuer's private key or host.
- Correctness of the model's reasoning or tool implementation.
- OAuth authorization-server policy itself; SwarmAuth integrates at the
  resource/execution boundary.
- Denial of service against the transport or control plane.
- Removal of tokens from other clones, forks, or provider caches.

## Required invariants

- A verifier checks the signature using the exact public key named by `kid`.
- A token is bound to its audience and explicit capability set.
- A token with a stateful constraint cannot execute without a tracker.
- Delegation can only attenuate authority and is limited to one hop.
- The model cannot provide, forge, or omit the authorization token.
- Revocation is checked before execution when a revocation store is configured.
- Decision evidence excludes bearer tokens and private key material.
- Approval resolution trusts only the identity injected by the authenticated
  WSGI/reverse-proxy boundary; client-supplied identity headers are ignored.
- Unknown issuers and untrusted holder keys fail closed.

## Security testing strategy

- Shared cross-language vectors for canonicalization, signatures, time, and
  delegation.
- Property/adversarial tests for malformed claims and boundary values.
- Concurrent tests for usage and revocation stores.
- Real-framework tests for schema exposure and execution interception.
- Dependency audit on every CI run.
- External review before production claims or paid enterprise deployment.

## Residual risks

- A caller can still misuse an authority that was legitimately granted; policy
  quality and approval workflows remain necessary.
- In-memory trackers and registries are process-local; distributed deployments
  must use the Redis or equivalent shared implementations.
- The control-plane HTTP seam still depends on the deployment's OAuth/OIDC
  resolver, isolated tenant store, TLS termination, migrations, backups, and
  operational controls before it is suitable for production deployment.
