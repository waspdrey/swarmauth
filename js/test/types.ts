import { createClientPool } from "redis";
import {
  TokenIssuer, Grant, IssuerPolicy, publicKeyFromSeed, guard, asyncGuard,
  UsageTracker, BudgetRule, RedisUsageTracker, type AuthorizationEvent,
} from "swarmauth";
const seed = new Uint8Array(32);
const issuer = new TokenIssuer(seed, { policy: new IssuerPolicy([
  new Grant({ iss: "issuer", sub: "tool:x", capabilities: ["tool:x"], maxCalls: 1 }),
]) });
const token: string = issuer.issue({ iss: "issuer", sub: "tool:x", capabilities: ["tool:x"], constraints: { max_calls: 1 } });
const guarded = guard(({ value }: { value: string }) => value, {
  capability: "tool:x", publicKey: publicKeyFromSeed(seed), tracker: new UsageTracker(),
});
const result: string = guarded({ value: "safe", token });
const pool = createClientPool();
const tracker = new RedisUsageTracker(pool, { requireBudget: true, rules: [
  new BudgetRule({ id: "task", issuers: ["issuer"], currency: "GHS", maxAmountMinor: 100, expiresAt: 2000000000 }),
] });
const asyncTool = asyncGuard(async ({ value }: { value: string }) => value, {
  capability: "tool:x", publicKey: publicKeyFromSeed(seed), tracker,
  onDecision: async (event: AuthorizationEvent) => { void event; },
});
const promise: Promise<string> = asyncTool({ value: result, token });
void promise;
