# SwarmAuth

Signed, short-lived capability tokens for tool calls made by autonomous agents.

A token names the tool it is for, the capabilities it grants, and the limits on calls, spend, and parameters. Every token expires within 300 seconds. The signing key and the issuer policy stay in a process the model cannot call. The runtime attaches the token with `useToken` before the tool runs.

This package speaks the same [JCT](https://github.com/waspdrey/swarmauth/blob/main/SPEC.md) wire format as [swarmauth on PyPI](https://pypi.org/project/swarmauth/). Node.js 18 or newer. ECMAScript modules. No runtime dependencies.

## Install

```bash
npm install swarmauth
```

## Quickstart

`privateKey` is a 32-byte Ed25519 seed. Call `policy.check` before `issue`. `issue` signs whatever you pass it. The policy is what refuses a grant the issuer was not configured to make.

```js
import { randomBytes } from "node:crypto";
import {
  Grant,
  IssuerPolicy,
  SwarmAuthError,
  guard,
  issue,
  publicKeyFromSeed,
  useToken,
} from "swarmauth";

const privateKey = randomBytes(32);
const publicKey = publicKeyFromSeed(privateKey);

const request = {
  iss: "agent:requester-01",
  sub: "tool:process_payout",
  capabilities: ["tool:process_payout"],
  constraints: { max_calls: 1, max_amount_usd: 1000 },
  ttlSeconds: 60,
};

const policy = new IssuerPolicy([
  new Grant({
    iss: request.iss,
    sub: request.sub,
    capabilities: request.capabilities,
    maxTtlSeconds: 60,
    maxCalls: 1,
    maxAmountUsd: 1000,
  }),
]);

policy.check(request);
const token = issue({ privateKey, ...request });

const usage = new Map();
const tracker = {
  checkAndRecord(claims, amount = 0) {
    const state = usage.get(claims.jti) ?? { calls: 0, amount: 0 };
    const calls = state.calls + 1;
    const spent = state.amount + amount;
    if (claims.constraints.max_calls != null && calls > claims.constraints.max_calls) {
      throw new SwarmAuthError("CONSTRAINT_VIOLATION", "max_calls exceeded");
    }
    if (claims.constraints.max_amount_usd != null && spent > claims.constraints.max_amount_usd) {
      throw new SwarmAuthError("CONSTRAINT_VIOLATION", "max_amount_usd exceeded");
    }
    usage.set(claims.jti, { calls, amount: spent });
  },
};

const processPayout = guard(
  ({ destinationAccount, amountUsd }) => ({ destinationAccount, amountUsd, status: "sent" }),
  {
    capability: "tool:process_payout",
    publicKey,
    amountArg: "amountUsd",
    tracker,
  },
);

const receipt = useToken(token, () =>
  processPayout({ destinationAccount: "acct_123", amountUsd: 50 }),
);
```

`guard` binds the audience to the capability string. Pass `audience` when the token's `sub` is different. A token that sets `max_calls`, `max_amount_usd`, or `rate_limit_per_min` is rejected when `tracker` is omitted. The tracker above is the smallest counter that enforces those two ceilings. Share one tracker across every verifier that must see the same usage.

Wire-format constraint fields stay snake_case (`max_calls`, `max_amount_usd`, `rate_limit_per_min`, `allowed_params`). Grant fields on `Grant` are camelCase (`maxCalls`, `maxAmountUsd`, `maxTtlSeconds`).

## One-hop delegation

A parent token can name one worker in `dlg`. That worker calls `attenuate` once and receives a narrower child. The child cannot be delegated again. Presenting the parent itself to a tool fails with `DELEGATION_VIOLATION`.

Register the root key with `register` and the worker key with `registerHolder`. A holder key is not a root issuer.

```js
import { randomBytes } from "node:crypto";
import { KeyRegistry, attenuate, issue, publicKeyFromSeed, verify } from "swarmauth";

const rootKey = randomBytes(32);
const workerKey = randomBytes(32);

const parent = issue({
  privateKey: rootKey,
  iss: "agent:root",
  sub: "tool:process_payout",
  capabilities: ["tool:process_payout"],
  constraints: { max_calls: 1, max_amount_usd: 1000 },
  ttlSeconds: 60,
  dlg: "agent:worker",
});

const child = attenuate({
  privateKey: workerKey,
  parent,
  iss: "agent:worker",
  capabilities: ["tool:process_payout"],
  constraints: { max_calls: 1, max_amount_usd: 50 },
  ttlSeconds: 30,
});

const registry = new KeyRegistry();
registry.register("agent:root", publicKeyFromSeed(rootKey));
registry.registerHolder("agent:worker", publicKeyFromSeed(workerKey));

const claims = verify(child, { registry, audience: "tool:process_payout" });
```

## Errors

Failures throw `SwarmAuthError`. `error.code` is one of:

`MALFORMED_TOKEN`, `INVALID_SIGNATURE`, `UNKNOWN_ISSUER`, `TOKEN_EXPIRED`, `TOKEN_NOT_YET_VALID`, `TOKEN_REVOKED`, `AUDIENCE_MISMATCH`, `CAPABILITY_VIOLATION`, `CONSTRAINT_VIOLATION`, `DELEGATION_VIOLATION`, `POLICY_VIOLATION`.

## Protocol

Claim layout, canonical JSON, and verification order are specified in [SPEC.md](https://github.com/waspdrey/swarmauth/blob/main/SPEC.md). The Python SDK is [swarmauth on PyPI](https://pypi.org/project/swarmauth/).
