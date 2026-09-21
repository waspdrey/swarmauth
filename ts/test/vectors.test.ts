/**
 * Verifies this TypeScript implementation against spec/test-vectors/vectors.json
 * -- the same conformance file the Python reference SDK enforces itself
 * against in tests/test_spec_vectors.py. If both implementations pass
 * against the same file, they're interoperable by construction, not by
 * inspection.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  AudienceMismatchError,
  CapabilityViolationError,
  ConstraintViolationError,
  InvalidSignatureError,
  KeyPair,
  MalformedTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
  TokenRevokedError,
  UnknownIssuerError,
  buildToken,
  verify,
} from "../src/index.js";
import type { CapabilityClaims } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// ts/dist/test/ -> ts/dist -> ts -> repo root
const vectorsPath = path.join(__dirname, "..", "..", "..", "spec", "test-vectors", "vectors.json");
const vectorsData = JSON.parse(readFileSync(vectorsPath, "utf-8"));

const ERROR_CODE_TO_CLASS: Record<string, new (message: string) => Error> = {
  MALFORMED_TOKEN: MalformedTokenError,
  INVALID_SIGNATURE: InvalidSignatureError,
  TOKEN_EXPIRED: TokenExpiredError,
  TOKEN_NOT_YET_VALID: TokenNotYetValidError,
  TOKEN_REVOKED: TokenRevokedError,
  UNKNOWN_ISSUER: UnknownIssuerError,
  AUDIENCE_MISMATCH: AudienceMismatchError,
  CAPABILITY_VIOLATION: CapabilityViolationError,
  CONSTRAINT_VIOLATION: ConstraintViolationError,
};

test("vectors.json has the expected shape", () => {
  assert.ok(Array.isArray(vectorsData.vectors) && vectorsData.vectors.length > 0);
  assert.ok(Array.isArray(vectorsData.temporal_test_cases) && vectorsData.temporal_test_cases.length > 0);
  assert.equal(vectorsData.issuer_private_key_seed_hex.length, 64);
  assert.equal(vectorsData.issuer_public_key_hex.length, 64);
});

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

test("the fixed test seed derives the published public key", async () => {
  const keyPair = await KeyPair.fromPrivateBytes(hexToBytes(vectorsData.issuer_private_key_seed_hex));
  assert.equal(Buffer.from(keyPair.publicBytes).toString("hex"), vectorsData.issuer_public_key_hex);
});

for (const vector of vectorsData.vectors as Array<Record<string, unknown>>) {
  test(`vector: ${vector.name}`, async (t) => {
    const issuerPublicKey = hexToBytes(vectorsData.issuer_public_key_hex as string);
    const token = vector.token as string;

    // See spec/test-vectors/README.md: iat/exp are fixed for byte
    // reproducibility, so pin the clock to just after the vector's own
    // iat rather than let it fail against real wall-clock drift.
    if (vector.claims) {
      const claims = vector.claims as { iat: number };
      t.mock.timers.enable({ apis: ["Date"] });
      t.mock.timers.setTime((claims.iat + 10) * 1000);
    }

    if (vector.valid) {
      const claims = await verify(token, { issuerPublicKey });
      const expected = vector.claims as Record<string, unknown>;
      assert.equal(claims.iss, expected.iss);
      assert.equal(claims.jti, expected.jti);
      assert.deepEqual(claims.capabilities, expected.capabilities);
    } else {
      const ExpectedError = ERROR_CODE_TO_CLASS[vector.error_code as string];
      assert.ok(ExpectedError, `no TS class mapped for error_code ${vector.error_code}`);
      await assert.rejects(() => verify(token, { issuerPublicKey }), ExpectedError);
    }
  });
}

for (const testCase of vectorsData.temporal_test_cases as Array<Record<string, unknown>>) {
  test(`temporal: ${testCase.name}`, async (t) => {
    const keyPair = await KeyPair.fromPrivateBytes(hexToBytes(vectorsData.issuer_private_key_seed_hex));
    const claims: CapabilityClaims = {
      iss: "agent:requester-01",
      sub: "tool:x",
      capabilities: ["tool:x"],
      constraints: { maxCalls: null, maxAmountUsd: null, rateLimitPerMin: null, allowedParams: {} },
      iat: testCase.iat as number,
      exp: testCase.exp as number,
      jti: `temporal-${testCase.name}`,
    };
    const token = await buildToken(keyPair, claims);

    t.mock.timers.enable({ apis: ["Date"] });
    t.mock.timers.setTime((testCase.now as number) * 1000);

    const verifyOptions = { issuerPublicKey: keyPair.publicBytes, leewaySeconds: testCase.leeway_seconds as number };
    if (testCase.expect_valid) {
      await verify(token, verifyOptions);
    } else {
      const ExpectedError = ERROR_CODE_TO_CLASS[testCase.error_code as string];
      assert.ok(ExpectedError, `no TS class mapped for error_code ${testCase.error_code}`);
      await assert.rejects(() => verify(token, verifyOptions), ExpectedError);
    }
  });
}
