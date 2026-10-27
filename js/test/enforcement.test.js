import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  InMemoryRevocationStore, KeyRegistry, UsageTracker, attenuate, guard, issue,
  parse, publicKeyFromSeed, verify, verifyAndCheck,
} from "../src/index.js";

const seed = Buffer.alloc(32, 7);
const publicKey = publicKeyFromSeed(seed);
const worker = Buffer.alloc(32, 8);
const reject = (fn) => assert.throws(fn, (error) => error.code === "CONSTRAINT_VIOLATION");
const mint = (constraints = {}) => issue({ privateKey: seed, iss: "root", sub: "tool:pay", capabilities: ["tool:pay"], constraints });

for (const constraints of [{ max_calls: 1 }, { max_amount_usd: 100 }, { rate_limit_per_min: 1 }]) {
  test(`siblings share parent limits: ${JSON.stringify(constraints)}`, () => {
    const registry = new KeyRegistry();
    registry.register("root", publicKey);
    registry.registerHolder("worker", publicKeyFromSeed(worker));
    const parent = issue({ privateKey: seed, iss: "root", sub: "tool:pay", capabilities: ["tool:pay"], constraints, dlg: "worker", ttlSeconds: 30 });
    const children = [0, 1, 2].map(() => attenuate({ privateKey: worker, parent, iss: "worker", capabilities: ["tool:pay"], constraints, ttlSeconds: 20 }));
    const tracker = new UsageTracker();
    verifyAndCheck(children[0], { registry, tracker, amount: 100 });
    for (const child of children.slice(1)) reject(() => verifyAndCheck(child, { registry, tracker, amount: 100 }));
  });
}

test("failed child reservation leaves parent allowance available", () => {
  const parent = { jti: "parent", exp: Date.now() / 1000 + 30, constraints: { max_calls: 2 } };
  const a = { jti: "a", exp: parent.exp, constraints: { max_calls: 1 } };
  const b = { ...a, jti: "b" };
  const tracker = new UsageTracker();
  tracker.checkAndRecordChain([parent, a]);
  reject(() => tracker.checkAndRecordChain([parent, a]));
  tracker.checkAndRecordChain([parent, b]);
  assert.equal(tracker.usage.get("parent").calls, 2);
});

test("budgeted tools require amount mapping, accept explicit zero, and reject invalid amounts", () => {
  const token = mint({ max_amount_usd: 100 });
  const tracker = new UsageTracker();
  const unmapped = guard(() => assert.fail("must not execute"), { capability: "tool:pay", publicKey, tracker });
  reject(() => unmapped({ token, amount: 50000 }));
  const mapped = guard(({ amount }) => amount, { capability: "tool:pay", publicKey, tracker, amountArg: "amount" });
  assert.equal(mapped({ token, amount: 0 }), 0);
  for (const amount of [undefined, null, NaN, Infinity, -1, true, "50"]) reject(() => mapped({ token, amount }));
  assert.equal(mapped({ token, amount: 100 }), 100);
  reject(() => mapped({ token, amount: 1 }));
});

test("parameter pins require presence, matching JSON types, and structural equality", () => {
  const token = mint({ allowed_params: { approved: true, optional: null, order: { id: 1, label: "Accra" } } });
  for (const params of [undefined, {}, { approved: 1 }, { approved: true, order: { id: 1, label: "Accra" } }]) {
    reject(() => verifyAndCheck(token, { publicKey, params }));
  }
  verifyAndCheck(token, { publicKey, params: { approved: true, optional: null, order: { label: "Accra", id: 1 } } });
});

test("guard forwards revocations and keeps them throughout the grace period", (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 1000000 });
  const token = mint();
  const claims = parse(token).claims;
  const store = new InMemoryRevocationStore();
  store.revoke(claims.jti, { expiresAt: claims.exp });
  const tool = guard(() => assert.fail("revoked tool executed"), { capability: "tool:pay", publicKey, revocationStore: store });
  for (const now of [1000000, (claims.exp + 1) * 1000, (claims.exp + 2) * 1000 + 999]) {
    t.mock.timers.setTime(now);
    assert.throws(() => tool({ token }), (error) => error.code === "TOKEN_REVOKED");
  }
  t.mock.timers.setTime((claims.exp + 3) * 1000);
  assert.equal(store.isRevoked(claims.jti), false);
});

test("decision events omit credentials and tool arguments", () => {
  const events = [];
  const token = mint({ max_calls: 1 });
  const tool = guard(() => "ok", { capability: "tool:pay", publicKey, tracker: new UsageTracker(), onDecision: (event) => events.push(event) });
  assert.equal(tool({ token, secret: "do-not-log" }), "ok");
  reject(() => tool({ token, secret: "do-not-log" }));
  assert.deepEqual(events.map((event) => event.decision), ["allowed", "denied"]);
  assert.ok(!JSON.stringify(events).includes(token));
  assert.ok(!JSON.stringify(events).includes("do-not-log"));
});

test("SDK signs Unicode, nested booleans, and whole-dollar budgets exactly like Python", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../spec/test-vectors/vectors.json", import.meta.url), "utf8"));
  const vector = vectors.vectors.find((item) => item.name === "unicode_and_nested_pins");
  const token = issue({ privateKey: Buffer.from(vectors.issuer_private_key_seed_hex, "hex"), ...vector.claims });
  assert.equal(token, vector.token);
});
