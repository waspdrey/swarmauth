import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { once } from "node:events";
import test from "node:test";
import express from "express";
import { createClientPool } from "redis";
import {
  BudgetRule, BudgetUsageTracker, RedisUsageTracker, TokenIssuer, Grant, IssuerPolicy,
  KeyRegistry, UsageTracker, InMemoryRevocationStore, asyncGuard, asyncVerifyAndCheck,
  guard, issue, parse, publicKeyFromSeed, tokenContextMiddleware, verify, verifyAndCheck,
} from "../src/index.js";

const keys = () => { const seed = randomBytes(32); return { seed, publicKey: publicKeyFromSeed(seed) }; };
const token = (seed, constraints = {}) => issue({ privateKey: seed, iss: "issuer", sub: "tool:x",
  capabilities: ["tool:x"], ttlSeconds: 30, constraints });
const code = (expected) => (error) => error.code === expected;

test("policy-bound issuer cannot override its signing key or policy TTL", () => {
  const { seed } = keys();
  const issuer = new TokenIssuer(seed, { policy: new IssuerPolicy([
    new Grant({ iss: "issuer", sub: "tool:x", capabilities: ["tool:x"], maxTtlSeconds: 10, maxCalls: 1 }),
  ]) });
  const request = { iss: "issuer", sub: "tool:x", capabilities: ["tool:x"], constraints: { max_calls: 1 } };
  assert.equal(parse(issuer.issue(request)).claims.exp - parse(issuer.issue(request)).claims.iat, 10);
  assert.throws(() => issuer.issue({ ...request, capabilities: ["tool:other"] }), code("POLICY_VIOLATION"));
  assert.throws(() => issuer.issue({ ...request, exp: Math.floor(Date.now() / 1000) + 30 }), /cannot be overridden/);
  assert.throws(() => new TokenIssuer(seed), /IssuerPolicy/);
});

test("key registry revokes root and holder keys and returns defensive copies", () => {
  const { seed, publicKey } = keys(), registry = new KeyRegistry();
  registry.register("issuer", publicKey);
  registry.registerHolder("worker", publicKey);
  registry.keysFor("issuer")[0].fill(0);
  verify(token(seed), { registry });
  registry.revokeHolder("worker", publicKey);
  assert.throws(() => registry.holderKeysFor("worker"), code("UNKNOWN_ISSUER"));
  registry.revoke("issuer", publicKey);
  assert.throws(() => verify(token(seed), { registry }), code("UNKNOWN_ISSUER"));
});

test("USD accounting adds decimal amounts exactly", () => {
  const { seed, publicKey } = keys(), tracker = new UsageTracker();
  const credential = token(seed, { max_amount_usd: 0.3 });
  for (const amount of [0.1, 0.2]) verifyAndCheck(credential, { publicKey, tracker, amount });
  assert.throws(() => verifyAndCheck(credential, { publicKey, tracker, amount: 1e-12 }), code("CONSTRAINT_VIOLATION"));
});

test("async authorization awaits stores and callback before executing", async () => {
  const { seed, publicKey } = keys(), sequence = [];
  const tool = asyncGuard(async () => { sequence.push("executed"); }, { capability: "tool:x", publicKey,
    tracker: { async checkAndRecord() { await Promise.resolve(); sequence.push("reserved"); } },
    async onDecision(event) { await Promise.resolve(); sequence.push(event.decision); },
  });
  await tool({ token: token(seed, { max_calls: 1 }) });
  assert.deepEqual(sequence, ["reserved", "allowed", "executed"]);
  await assert.rejects(asyncVerifyAndCheck(token(seed, { max_calls: 1 }), { publicKey,
    tracker: { async checkAndRecord() { throw new Error("store unavailable"); } },
  }), /store unavailable/);
  const revoked = new InMemoryRevocationStore(), credential = token(seed);
  revoked.revoke(parse(credential).claims.jti, { expiresAt: parse(credential).claims.exp });
  await assert.rejects(asyncVerifyAndCheck(credential, { publicKey,
    revocationStore: { async isRevoked(jti) { return revoked.isRevoked(jti); } },
  }), code("TOKEN_REVOKED"));
});

test("fresh tokens share a currency budget and pins bind actual parameters", () => {
  const { seed, publicKey } = keys();
  const tracker = new BudgetUsageTracker([
    new BudgetRule({ id: "task", issuers: ["issuer"], currency: "GHS", maxAmountMinor: 100,
      expiresAt: Math.floor(Date.now() / 1000) + 3600 }),
  ]);
  const call = (amount, overrides = {}) => {
    const params = { budget_id: "task", currency: "GHS", amount_minor: amount };
    const credential = token(seed, { max_calls: 1, shared_budget: "task", allowed_params: params });
    return verifyAndCheck(credential, { publicKey, tracker, params: { ...params, ...overrides } });
  };
  assert.throws(() => call(60, { amount_minor: 1 }), code("CONSTRAINT_VIOLATION"));
  call(60);
  assert.throws(() => call(50), code("CONSTRAINT_VIOLATION"));
  call(40);
  assert.throws(() => call(1), code("CONSTRAINT_VIOLATION"));
});

test("shared-budget marker fails closed without an aware tracker and signs Python bytes", () => {
  const { seed, publicKey } = keys();
  const params = { budget_id: "task", currency: "GHS", amount_minor: 10 };
  const credential = token(seed, { shared_budget: "task", allowed_params: params });
  for (const tracker of [undefined, new UsageTracker()]) {
    assert.throws(() => verifyAndCheck(credential, { publicKey, params, tracker }), code("CONSTRAINT_VIOLATION"));
  }
  const vectors = JSON.parse(readFileSync(new URL("../../spec/test-vectors/vectors.json", import.meta.url), "utf8"));
  const vector = vectors.vectors.find((item) => item.name === "shared_budget_valid");
  const signed = issue({ privateKey: Buffer.from(vectors.issuer_private_key_seed_hex, "hex"), ...vector.claims,
    ttlSeconds: vector.claims.exp - vector.claims.iat });
  assert.equal(signed, vector.token);
});

test("Express propagation isolates concurrent bearer credentials", async (t) => {
  const { seed, publicKey } = keys();
  const guarded = asyncGuard(async ({ value }) => { await new Promise((resolve) => setImmediate(resolve)); return value; },
    { capability: "tool:x", publicKey });
  const app = express();
  app.use(tokenContextMiddleware());
  app.get("/:value", async (req, res) => res.json({ value: await guarded({ value: req.params.value }) }));
  app.use((error, _req, res, _next) => res.status(403).json({ error: error.code ?? "DENIED" }));
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const responses = await Promise.all(["first", "second"].map(async (value) => {
    const credential = token(seed, { allowed_params: { value } });
    return (await fetch(`${base}/${value}`, { headers: { authorization: `Bearer ${credential}` } })).json();
  }));
  assert.deepEqual(responses, [{ value: "first" }, { value: "second" }]);
  assert.equal((await fetch(`${base}/missing`)).status, 401);
});

test("native async Redis reservations are atomic across clients and fresh tokens", {
  skip: !process.env.SWARMAUTH_TEST_REDIS_URL,
  timeout: 15000,
}, async (t) => {
  const pool = createClientPool({ url: process.env.SWARMAUTH_TEST_REDIS_URL,
    socket: { connectTimeout: 2000, reconnectStrategy: false } }, { minimum: 1, maximum: 8 });
  pool.on("error", () => {});
  await pool.connect();
  t.after(() => pool.close());
  const { seed, publicKey } = keys();
  const tracker = new RedisUsageTracker(pool, { keyPrefix: `swarmauth:test:${randomBytes(8).toString("hex")}:`,
    requireBudget: true, rules: [{ id: "task", issuers: ["issuer"], currency: "GHS", maxAmountMinor: 100,
      expiresAt: Math.floor(Date.now() / 1000) + 3600 }] });
  const params = { budget_id: "task", currency: "GHS", amount_minor: 10 };
  const attempts = await Promise.allSettled(Array.from({ length: 20 }, () => asyncVerifyAndCheck(
    token(seed, { max_calls: 1, shared_budget: "task", allowed_params: params }), { publicKey, tracker, params },
  )));
  assert.equal(attempts.filter((item) => item.status === "fulfilled").length, 10);
  assert.ok(attempts.filter((item) => item.status === "rejected").every((item) => item.reason.code === "CONSTRAINT_VIOLATION"));
  const replayTracker = new RedisUsageTracker(pool, { keyPrefix: `swarmauth:test:${randomBytes(8).toString("hex")}:` });
  const credential = token(seed, { max_calls: 1 });
  await asyncVerifyAndCheck(credential, { publicKey, tracker: replayTracker });
  await assert.rejects(asyncVerifyAndCheck(credential, { publicKey, tracker: replayTracker }), code("CONSTRAINT_VIOLATION"));
  assert.throws(() => guard(() => assert.fail("must not execute"), { capability: "tool:x", publicKey,
    tracker: replayTracker })({ token: token(seed, { max_calls: 1 }) }), /synchronous/);
});
