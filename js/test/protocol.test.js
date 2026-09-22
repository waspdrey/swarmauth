import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  Grant,
  IssuerPolicy,
  KeyRegistry,
  attenuate,
  canonicalJson,
  checkLifetime,
  guard,
  issue,
  publicKeyFromSeed,
  useToken,
  verify,
  verifyAndCheck,
} from "../src/index.js";

const vectors = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "spec", "test-vectors", "vectors.json"), "utf8"),
);
const seed = Buffer.from(vectors.issuer_private_key_seed_hex, "hex");
const publicKey = Buffer.from(vectors.issuer_public_key_hex, "hex");

test("seed matches the published public key", () => {
  assert.equal(publicKeyFromSeed(seed).toString("hex"), vectors.issuer_public_key_hex);
});

test("canonical claims match signing_input where JSON keeps the Python number text", () => {
  const names = new Set([
    "minimal_valid",
    "full_constraints_and_wildcard",
    "ttl_exceeds_max",
    "tampered_signature",
    "kid_does_not_match_signing_key",
  ]);
  for (const vector of vectors.vectors) {
    if (!names.has(vector.name)) continue;
    const built = `${Buffer.from(canonicalJson(vector.header)).toString("base64url")}.${Buffer.from(canonicalJson(vector.claims)).toString("base64url")}`;
    assert.equal(built, vector.signing_input, vector.name);
  }
});

test("vectors verify with the published outcomes", () => {
  for (const vector of vectors.vectors) {
    const now = vector.claims ? vector.claims.iat + 10 : undefined;
    const options = trust(vector);
    if (now != null) options.now = now;
    if (vector.valid) {
      const claims = verify(vector.token, options);
      assert.equal(claims.iss, vector.claims.iss);
      assert.equal(claims.jti, vector.claims.jti);
    } else {
      assert.throws(() => verify(vector.token, options), (error) => error.code === vector.error_code);
    }
  }
});

test("temporal cases", () => {
  for (const item of vectors.temporal_test_cases) {
    if (item.expect_valid) {
      checkLifetime(item);
    } else {
      assert.throws(
        () => checkLifetime({ iat: item.iat, exp: item.exp, leewaySeconds: item.leeway_seconds, now: item.now }),
        (error) => error.code === item.error_code,
      );
    }
  }
});

test("issue rejects a ttl above 300 and encodes whole-number amounts as floats", () => {
  assert.throws(() => issue({ privateKey: seed, iss: "a", sub: "b", capabilities: ["x"], ttlSeconds: 301 }), /300/);
  const token = issue({
    privateKey: seed,
    iss: "a",
    sub: "b",
    capabilities: ["x"],
    ttlSeconds: 60,
    constraints: { max_amount_usd: 40, max_calls: 1 },
    iat: 1_700_000_000,
    exp: 1_700_000_060,
    jti: "fixed",
  });
  const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  assert.equal(Object.hasOwn(payload, "dlg"), false);
  const raw = Buffer.from(token.split(".")[1], "base64url").toString("utf8");
  assert.match(raw, /40\.0/);
  assert.equal(payload.constraints.max_calls, 1);
});

test("policy, runtime token, and one-hop attenuation", () => {
  const root = seed;
  const worker = Buffer.from("20".repeat(32), "hex");
  const policy = new IssuerPolicy([
    new Grant({
      iss: "agent:root",
      sub: "tool:pay",
      capabilities: ["tool:pay"],
      maxTtlSeconds: 60,
      maxCalls: 1,
      delegates: ["agent:worker"],
    }),
  ]);
  assert.throws(
    () =>
      policy.check({
        iss: "agent:root",
        sub: "tool:pay",
        capabilities: ["tool:admin"],
        ttlSeconds: 60,
        constraints: { max_calls: 1 },
      }),
    (error) => error.code === "POLICY_VIOLATION",
  );
  policy.check({
    iss: "agent:root",
    sub: "tool:pay",
    capabilities: ["tool:pay"],
    ttlSeconds: 60,
    constraints: { max_calls: 1 },
    dlg: "agent:worker",
  });

  const parent = issue({
    privateKey: root,
    iss: "agent:root",
    sub: "tool:pay",
    capabilities: ["tool:pay"],
    ttlSeconds: 60,
    dlg: "agent:worker",
    constraints: { max_calls: 1 },
  });
  const registry = new KeyRegistry();
  registry.register("agent:root", publicKeyFromSeed(root));
  registry.registerHolder("agent:worker", publicKeyFromSeed(worker));
  assert.throws(() => verify(parent, { registry, audience: "tool:pay" }), (error) => error.code === "DELEGATION_VIOLATION");

  const child = attenuate({
    privateKey: worker,
    parent,
    iss: "agent:worker",
    capabilities: ["tool:pay"],
    constraints: { max_calls: 1 },
    ttlSeconds: 30,
  });
  const claims = verify(child, { registry, audience: "tool:pay" });
  assert.equal(claims.iss, "agent:worker");

  const calls = [];
  const tool = guard((args) => calls.push(args.amount), {
    capability: "tool:pay",
    registry,
    tracker: { checkAndRecord() {} },
  });
  useToken(child, () => tool({ amount: 1 }));
  assert.deepEqual(calls, [1]);
  assert.throws(() => tool({ amount: 1 }), (error) => error.code === "CAPABILITY_VIOLATION");
});

test("stateful constraints fail closed without a tracker", () => {
  const token = issue({
    privateKey: seed,
    iss: "a",
    sub: "b",
    capabilities: ["b"],
    ttlSeconds: 60,
    constraints: { max_calls: 1 },
  });
  assert.throws(
    () => verifyAndCheck(token, { publicKey, requiredCapability: "b" }),
    (error) => error.code === "CONSTRAINT_VIOLATION",
  );
});

function trust(vector) {
  if (!vector.delegate_public_key_hex) return { publicKey };
  const registry = new KeyRegistry();
  registry.register(vector.root_iss, publicKey);
  registry.registerHolder(vector.delegate_iss, Buffer.from(vector.delegate_public_key_hex, "hex"));
  return { registry };
}
