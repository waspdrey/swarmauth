/**
 * SwarmAuth for JavaScript. Same JCT wire format as the Python reference SDK.
 * Verify tokens against spec/test-vectors/vectors.json before trusting a change.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { createPrivateKey, createPublicKey, randomBytes, sign, verify as verifyEd25519 } from "node:crypto";

export { asyncGuard, asyncVerifyAndCheck, tokenContextMiddleware } from "./async.js";
export { BudgetRule, BudgetUsageTracker, RedisUsageTracker } from "./redis.js";

export const MAX_TTL_SECONDS = 30;
export const MAX_LEEWAY_SECONDS = 2;
export const RETENTION_AFTER_EXP_SECONDS = MAX_LEEWAY_SECONDS + 1;
const TOKEN_TYPE = "JCT";
const ALG = "EdDSA";
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const tokenContext = new AsyncLocalStorage();

export class SwarmAuthError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SwarmAuthError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new SwarmAuthError(code, message);
}

export function b64urlEncode(data) {
  return Buffer.from(data).toString("base64url");
}

export function b64urlDecode(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) {
    fail("MALFORMED_TOKEN", "Invalid base64url");
  }
  const bytes = Buffer.from(text, "base64url");
  if (b64urlEncode(bytes) !== text) fail("MALFORMED_TOKEN", "Non-canonical base64url");
  return bytes;
}

function formatAmount(value) {
  if (!Number.isFinite(value)) fail("CONSTRAINT_VIOLATION", "max_amount_usd must be finite");
  if (Number.isInteger(value)) return value.toFixed(1);
  return JSON.stringify(value);
}

function encodeString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function compareKeys(a, b) {
  const left = Array.from(a, (ch) => ch.codePointAt(0));
  const right = Array.from(b, (ch) => ch.codePointAt(0));
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function encode(value) {
  if (value === null) return "null";
  if (typeof value === "string") return encodeString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("MALFORMED_TOKEN", "non-finite number in claims");
    if (Number.isInteger(value)) return String(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(encode).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(compareKeys);
    return `{${keys.map((key) => `${encodeString(key)}:${encode(value[key])}`).join(",")}}`;
  }
  fail("MALFORMED_TOKEN", "unsupported JSON value");
}

export function canonicalJson(value) {
  return encode(value);
}

function constraintsWire(constraints = {}) {
  const allowed = constraints.allowed_params ?? {};
  const amount = constraints.max_amount_usd == null ? "null" : formatAmount(constraints.max_amount_usd);
  const calls = constraints.max_calls == null ? "null" : String(constraints.max_calls);
  const rate = constraints.rate_limit_per_min == null ? "null" : String(constraints.rate_limit_per_min);
  const budget = constraints.shared_budget == null ? "" : `,"shared_budget":${encode(constraints.shared_budget)}`;
  return `{"allowed_params":${encode(allowed)},"max_amount_usd":${amount},"max_calls":${calls},"rate_limit_per_min":${rate}${budget}}`;
}

function claimsWire(claims) {
  const body = {
    capabilities: claims.capabilities,
    constraints: claims.constraints,
    exp: claims.exp,
    iat: claims.iat,
    iss: claims.iss,
    jti: claims.jti,
    sub: claims.sub,
  };
  if (claims.dlg) body.dlg = claims.dlg;
  if (claims.prf) body.prf = claims.prf;
  const encoded = encode(body);
  return encoded.replace(
    `"constraints":${encode(claims.constraints)}`,
    `"constraints":${constraintsWire(claims.constraints)}`,
  );
}

function privateKeyFromSeed(seed) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: "der", type: "pkcs8" });
}

function publicKeyFromRaw(raw) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]), format: "der", type: "spki" });
}

export function publicKeyFromSeed(seed) {
  const key = createPublicKey(privateKeyFromSeed(seed));
  const der = key.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32);
}

function requireTtl(ttlSeconds) {
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new Error(`ttlSeconds must be an integer from 1 to ${MAX_TTL_SECONDS}`);
  }
}

function signToken(seed, claims) {
  const publicKey = publicKeyFromSeed(seed);
  const header = { alg: ALG, kid: b64urlEncode(publicKey), typ: TOKEN_TYPE };
  const headerB64 = b64urlEncode(Buffer.from(canonicalJson(header)));
  const payloadB64 = b64urlEncode(Buffer.from(claimsWire(claims)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = sign(null, Buffer.from(signingInput), privateKeyFromSeed(seed));
  return `${signingInput}.${b64urlEncode(signature)}`;
}

export function issue({ privateKey, iss, sub, capabilities, constraints, ttlSeconds = 10, dlg, iat, exp, jti }) {
  const seed = Buffer.from(privateKey);
  if (seed.length !== 32) throw new Error("privateKey must be a 32-byte Ed25519 seed");
  requireTtl(ttlSeconds);
  const now = iat ?? Math.floor(Date.now() / 1000);
  const claims = {
    iss,
    sub,
    capabilities,
    constraints: emptyConstraints(constraints),
    iat: now,
    exp: exp ?? now + ttlSeconds,
    jti: jti ?? b64urlEncode(randomBytes(16)),
  };
  if (dlg) claims.dlg = dlg;
  validateClaims({ ...claims, constraints: constraints ?? {} });
  return signToken(seed, claims);
}

function emptyConstraints(constraints = {}) {
  return {
    allowed_params: constraints.allowed_params ?? {},
    max_amount_usd: constraints.max_amount_usd ?? null,
    max_calls: constraints.max_calls ?? null,
    rate_limit_per_min: constraints.rate_limit_per_min ?? null,
    ...(constraints.shared_budget != null ? { shared_budget: constraints.shared_budget } : {}),
  };
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
  if (Array.isArray(value)) return value.every(validJson);
  return isObject(value) && Object.values(value).every(validJson);
}

function validateClaims(claims) {
  const fields = new Set(["iss", "sub", "capabilities", "constraints", "iat", "exp", "jti", "dlg", "prf"]);
  if (!isObject(claims) || Object.keys(claims).some((key) => !fields.has(key)) ||
      !["iss", "sub", "jti"].every((key) => typeof claims[key] === "string" && claims[key].length > 0) ||
      !Array.isArray(claims.capabilities) || claims.capabilities.length === 0 ||
      !claims.capabilities.every((item) => typeof item === "string" && item.length > 0) ||
      !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.exp <= claims.iat) {
    fail("MALFORMED_TOKEN", "Invalid claims schema");
  }
  for (const key of ["dlg", "prf"]) {
    if (claims[key] != null && (typeof claims[key] !== "string" || claims[key].length === 0)) {
      fail("MALFORMED_TOKEN", `Invalid ${key}`);
    }
  }
  if (claims.constraints === null) fail("MALFORMED_TOKEN", "Invalid constraints");
  const limits = claims.constraints ?? {};
  const names = new Set(["max_calls", "max_amount_usd", "rate_limit_per_min", "allowed_params", "shared_budget"]);
  if (!isObject(limits) || Object.keys(limits).some((key) => !names.has(key))) fail("MALFORMED_TOKEN", "Invalid constraints");
  for (const key of ["max_calls", "rate_limit_per_min"]) {
    if (limits[key] != null && (!Number.isSafeInteger(limits[key]) || limits[key] < 1)) {
      fail("MALFORMED_TOKEN", `Invalid ${key}`);
    }
  }
  if (limits.max_amount_usd != null && (typeof limits.max_amount_usd !== "number" ||
      !Number.isFinite(limits.max_amount_usd) || limits.max_amount_usd < 0)) fail("MALFORMED_TOKEN", "Invalid budget");
  if (Object.hasOwn(limits, "allowed_params") && (!isObject(limits.allowed_params) || !validJson(limits.allowed_params))) {
    fail("MALFORMED_TOKEN", "Invalid allowed_params");
  }
  if (limits.shared_budget != null) {
    const pins = limits.allowed_params ?? {};
    if (typeof limits.shared_budget !== "string" || !limits.shared_budget || pins.budget_id !== limits.shared_budget ||
      !Number.isSafeInteger(pins.amount_minor) || pins.amount_minor < 0 || typeof pins.currency !== "string" ||
      !/^[A-Z]{3}$/.test(pins.currency)) fail("MALFORMED_TOKEN", "Shared budgets require matching budget and monetary pins");
  }
}

export function parse(token) {
  if (typeof token !== "string") fail("MALFORMED_TOKEN", "Token must be a string");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) fail("MALFORMED_TOKEN", "Expected 3 non-empty segments");
  let header;
  let claims;
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    header = JSON.parse(decoder.decode(b64urlDecode(parts[0])));
    claims = JSON.parse(decoder.decode(b64urlDecode(parts[1])));
    b64urlDecode(parts[2]);
  } catch {
    fail("MALFORMED_TOKEN", "Token is not valid base64url JSON");
  }
  if (!isObject(header) || header.typ !== TOKEN_TYPE || header.alg !== ALG) fail("MALFORMED_TOKEN", "Unsupported token header");
  validateClaims(claims);
  return { header, claims: { ...claims, constraints: emptyConstraints(claims.constraints) }, signingInput: `${parts[0]}.${parts[1]}` };
}

function kidBytes(header) {
  if (typeof header.kid !== "string" || !header.kid) fail("MALFORMED_TOKEN", "Token header is missing kid");
  let raw;
  try {
    raw = b64urlDecode(header.kid);
  } catch {
    fail("MALFORMED_TOKEN", "Token kid is not valid base64url");
  }
  if (raw.length !== 32) fail("MALFORMED_TOKEN", "Token kid is not a 32-byte Ed25519 public key");
  return raw;
}

function sameKey(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function verifyKidAndSignature(header, claims, signingInput, signature, { publicKey, registry, holder }) {
  const kid = kidBytes(header);
  if (registry) {
    const trusted = holder ? registry.holderKeysFor(claims.iss) : registry.keysFor(claims.iss);
    if (!trusted.some((key) => sameKey(key, kid))) {
      fail("INVALID_SIGNATURE", `Token kid is not a trusted key for issuer '${claims.iss}'`);
    }
    if (!verifyEd25519(null, Buffer.from(signingInput), publicKeyFromRaw(kid), signature)) {
      fail("INVALID_SIGNATURE", "Ed25519 signature verification failed");
    }
    return;
  }
  if (holder) fail("DELEGATION_VIOLATION", "Delegated tokens require a key registry containing the root issuer and the delegate");
  if (!publicKey) throw new Error("Pass exactly one of publicKey or registry");
  if (!sameKey(publicKey, kid)) fail("INVALID_SIGNATURE", "Token kid does not match the trusted issuer public key");
  if (!verifyEd25519(null, Buffer.from(signingInput), publicKeyFromRaw(publicKey), signature)) {
    fail("INVALID_SIGNATURE", "Ed25519 signature verification failed");
  }
}

export function checkLifetime({ iat, exp, leewaySeconds = 2, now }) {
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) || exp <= iat) fail("MALFORMED_TOKEN", "Invalid lifetime");
  if (!Number.isInteger(leewaySeconds) || leewaySeconds < 0 || leewaySeconds > MAX_LEEWAY_SECONDS || !Number.isFinite(now)) {
    throw new RangeError("Invalid clock or leeway (must be 0..2 seconds)");
  }
  if (exp - iat > MAX_TTL_SECONDS) fail("TOKEN_EXPIRED", `Token TTL ${exp - iat}s exceeds max ${MAX_TTL_SECONDS}s`);
  if (now < iat - leewaySeconds) fail("TOKEN_NOT_YET_VALID", `Token not valid until ${iat}`);
  if (now > exp + leewaySeconds) fail("TOKEN_EXPIRED", `Token expired at ${exp}`);
}

function verifyCore(token, options, holder) {
  const { header, claims, signingInput } = parse(token);
  const signature = b64urlDecode(token.split(".")[2]);
  verifyKidAndSignature(header, claims, signingInput, signature, { ...options, holder });
  const now = options.now ?? Math.floor(Date.now() / 1000);
  checkLifetime({ iat: claims.iat, exp: claims.exp, leewaySeconds: options.leewaySeconds ?? 2, now });
  if (options.revocationStore?.isRevoked(claims.jti)) fail("TOKEN_REVOKED", `Token '${claims.jti}' has been revoked`);
  return claims;
}

export function capabilityCovered(capability, granted) {
  return granted.some((item) => item === capability || (item.endsWith(":*") && capability.startsWith(item.slice(0, -1))));
}

function limitIsWider(child, parent) {
  if (parent == null) return false;
  if (child == null || !Number.isFinite(child)) return true;
  return child > parent;
}

function assertAttenuated(parent, child) {
  if (parent.prf) fail("DELEGATION_VIOLATION", "Only one delegation hop is allowed");
  if (!parent.dlg || parent.dlg !== child.iss) {
    fail("DELEGATION_VIOLATION", `Parent token does not authorize '${child.iss}' to attenuate it`);
  }
  if (child.jti === parent.jti) fail("DELEGATION_VIOLATION", "Parent and child token IDs must differ");
  if (child.dlg) fail("DELEGATION_VIOLATION", "An attenuated token cannot itself be delegated further");
  if (child.sub !== parent.sub) fail("DELEGATION_VIOLATION", "Attenuated token retargets audience");
  if (child.iat < parent.iat || child.exp > parent.exp) {
    fail("DELEGATION_VIOLATION", "Attenuated token lifetime is outside the parent token's lifetime");
  }
  for (const capability of child.capabilities) {
    if (!capabilityCovered(capability, parent.capabilities)) {
      fail("DELEGATION_VIOLATION", `Attenuated capability '${capability}' exceeds the parent grant`);
    }
  }
  const parentConstraints = parent.constraints ?? {};
  const childConstraints = child.constraints ?? {};
  if (parentConstraints.shared_budget != null && childConstraints.shared_budget !== parentConstraints.shared_budget) {
    fail("DELEGATION_VIOLATION", "Attenuated token drops or changes shared budget");
  }
  for (const name of ["max_calls", "max_amount_usd", "rate_limit_per_min"]) {
    if (limitIsWider(childConstraints[name], parentConstraints[name])) {
      fail("DELEGATION_VIOLATION", `Attenuated ${name} widens the parent limit`);
    }
  }
  for (const [key, expected] of Object.entries(parentConstraints.allowed_params ?? {})) {
    if (!Object.hasOwn(childConstraints.allowed_params ?? {}, key) || !jsonEqual(childConstraints.allowed_params[key], expected)) {
      fail("DELEGATION_VIOLATION", `Attenuated token drops or changes pinned parameter '${key}'`);
    }
  }
}

export function verify(token, options = {}) {
  const preview = parse(token).claims;
  if (preview.prf && !options.registry) {
    fail("DELEGATION_VIOLATION", "Delegated tokens require a key registry containing the root issuer and the delegate");
  }
  const hasTrust = Boolean(options.publicKey) !== Boolean(options.registry);
  if (!hasTrust) throw new Error("Pass exactly one of publicKey or registry");
  const claims = verifyCore(token, options, Boolean(preview.prf));
  if (options.audience != null && claims.sub !== options.audience) {
    fail("AUDIENCE_MISMATCH", `Token audience '${claims.sub}' does not match '${options.audience}'`);
  }
  if (claims.prf) {
    const parentPreview = parse(claims.prf).claims;
    if (parentPreview.prf) fail("DELEGATION_VIOLATION", "Only one delegation hop is allowed");
    const parent = verifyCore(claims.prf, options, false);
    assertAttenuated(parent, claims);
  } else if (claims.dlg) {
    fail("DELEGATION_VIOLATION", "A delegable token cannot be presented to a tool; attenuate it first");
  }
  return claims;
}

export function attenuate({ privateKey, parent, iss, capabilities, constraints, ttlSeconds = 10 }) {
  requireTtl(ttlSeconds);
  const parentClaims = parse(parent).claims;
  const now = Math.floor(Date.now() / 1000);
  checkLifetime({ iat: parentClaims.iat, exp: parentClaims.exp, leewaySeconds: 0, now });
  const child = {
    iss,
    sub: parentClaims.sub,
    capabilities,
    constraints: emptyConstraints(constraints),
    iat: now,
    exp: now + ttlSeconds,
    jti: b64urlEncode(randomBytes(16)),
    prf: parent,
  };
  assertAttenuated(parentClaims, child);
  return signToken(Buffer.from(privateKey), child);
}

export class KeyRegistry {
  constructor() {
    this.roots = new Map();
    this.holders = new Map();
  }

  register(iss, publicKey, { rotate = false } = {}) {
    const key = Buffer.from(publicKey);
    const existing = this.roots.get(iss) ?? [];
    if (rotate && existing.length) {
      this.roots.set(iss, [key, ...existing.filter((item) => !item.equals(key))]);
    } else {
      this.roots.set(iss, [key]);
    }
  }

  registerHolder(iss, publicKey) {
    const key = Buffer.from(publicKey);
    const existing = (this.holders.get(iss) ?? []).filter((item) => !item.equals(key));
    this.holders.set(iss, [key, ...existing]);
  }

  revoke(iss, publicKey) {
    const keys = (this.roots.get(iss) ?? []).filter((key) => !sameKey(key, publicKey));
    if (keys.length) this.roots.set(iss, keys); else this.roots.delete(iss);
  }

  revokeHolder(iss, publicKey) {
    const keys = (this.holders.get(iss) ?? []).filter((key) => !sameKey(key, publicKey));
    if (keys.length) this.holders.set(iss, keys); else this.holders.delete(iss);
  }

  revokeIssuer(iss) { this.roots.delete(iss); this.holders.delete(iss); }

  keysFor(iss) {
    const keys = this.roots.get(iss);
    if (!keys?.length) fail("UNKNOWN_ISSUER", `No trusted key registered for issuer '${iss}'`);
    return keys.map((key) => Buffer.from(key));
  }

  holderKeysFor(iss) {
    const keys = this.holders.get(iss);
    if (!keys?.length) fail("UNKNOWN_ISSUER", `No holder key registered for delegate '${iss}'`);
    return keys.map((key) => Buffer.from(key));
  }
}

export class Grant {
  constructor(fields) {
    this.iss = fields.iss;
    this.sub = fields.sub;
    this.capabilities = [...fields.capabilities];
    this.maxTtlSeconds = fields.maxTtlSeconds ?? MAX_TTL_SECONDS;
    this.maxCalls = fields.maxCalls ?? null;
    this.maxAmountUsd = fields.maxAmountUsd ?? null;
    this.rateLimitPerMin = fields.rateLimitPerMin ?? null;
    this.delegates = [...(fields.delegates ?? [])];
    this.pinnedParams = { ...(fields.pinnedParams ?? {}) };
    validateClaims({ iss: this.iss, sub: this.sub, capabilities: this.capabilities, iat: 0, exp: 1, jti: "grant",
      constraints: { max_calls: this.maxCalls, max_amount_usd: this.maxAmountUsd,
        rate_limit_per_min: this.rateLimitPerMin, allowed_params: this.pinnedParams } });
    if (!Number.isInteger(this.maxTtlSeconds) || this.maxTtlSeconds <= 0 || this.maxTtlSeconds > MAX_TTL_SECONDS) {
      throw new Error(`maxTtlSeconds must be an integer from 1 to ${MAX_TTL_SECONDS}`);
    }
  }
}

export class IssuerPolicy {
  constructor(grants = []) {
    this.grants = [...grants];
  }

  check({ iss, sub, capabilities, constraints = {}, ttlSeconds, dlg }) {
    requireTtl(ttlSeconds);
    const candidates = this.grants.filter((grant) => grant.iss === iss && grant.sub === sub);
    if (!candidates.length) fail("POLICY_VIOLATION", `No grant allows '${iss}' to issue tokens for '${sub}'`);
    const reasons = [];
    for (const grant of candidates) {
      const reason = grantDenies(grant, { capabilities, constraints, ttlSeconds, dlg });
      if (!reason) return;
      reasons.push(reason);
    }
    fail("POLICY_VIOLATION", reasons.join("; "));
  }
}

/** Keep the policy check and signing inseparable. Explicit iat/exp/jti are
 * reserved for low-level conformance tooling, never accepted here. */
export class TokenIssuer {
  constructor(privateKey, { policy } = {}) {
    if (!(policy instanceof IssuerPolicy)) throw new TypeError("TokenIssuer requires an IssuerPolicy");
    this.privateKey = Buffer.from(privateKey);
    if (this.privateKey.length !== 32) throw new TypeError("Expected a 32-byte Ed25519 seed");
    this.policy = policy;
  }
  issue(request) {
    for (const field of ["iat", "exp", "jti", "privateKey", "prf"]) {
      if (Object.hasOwn(request, field)) throw new TypeError(`${field} cannot be overridden on TokenIssuer`);
    }
    const resolved = { ...request, ttlSeconds: request.ttlSeconds ?? 10 };
    this.policy.check(resolved);
    return issue({ ...resolved, privateKey: this.privateKey });
  }
  attenuate(request) {
    const parent = parse(request.parent).claims;
    const resolved = { ...request, ttlSeconds: request.ttlSeconds ?? 10 };
    if (Object.hasOwn(request, "privateKey")) throw new TypeError("privateKey cannot be overridden");
    this.policy.check({ ...resolved, sub: parent.sub, dlg: undefined });
    return attenuate({ ...resolved, privateKey: this.privateKey });
  }
}

function grantDenies(grant, { capabilities, constraints, ttlSeconds, dlg }) {
  for (const capability of capabilities) {
    if (!capabilityCovered(capability, grant.capabilities)) {
      return `Capability '${capability}' exceeds the grant for '${grant.iss}' -> '${grant.sub}'`;
    }
  }
  if (ttlSeconds > grant.maxTtlSeconds) return `ttlSeconds ${ttlSeconds} exceeds grant ceiling ${grant.maxTtlSeconds}`;
  if (limitIsWider(constraints.max_calls, grant.maxCalls)) return "max_calls exceeds the grant ceiling";
  if (limitIsWider(constraints.max_amount_usd, grant.maxAmountUsd)) return "max_amount_usd exceeds the grant ceiling";
  if (limitIsWider(constraints.rate_limit_per_min, grant.rateLimitPerMin)) return "rate_limit_per_min exceeds the grant ceiling";
  for (const [key, expected] of Object.entries(grant.pinnedParams)) {
    if (!Object.hasOwn(constraints.allowed_params ?? {}, key) || !jsonEqual(constraints.allowed_params[key], expected)) return `Issued token does not pin '${key}'`;
  }
  if (Object.hasOwn(grant.pinnedParams, "budget_id") && constraints.shared_budget !== grant.pinnedParams.budget_id) {
    return "Grant requires an explicit shared_budget constraint";
  }
  if (dlg != null && !grant.delegates.includes(dlg)) return `Grant does not allow delegation to '${dlg}'`;
  return null;
}

function jsonEqual(left, right) {
  if (left === right) return true;
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((item, index) => jsonEqual(item, right[index]));
  }
  if (isObject(left) && isObject(right)) {
    return Object.keys(left).length === Object.keys(right).length &&
      Object.keys(left).every((key) => Object.hasOwn(right, key) && jsonEqual(left[key], right[key]));
  }
  return false;
}

function validatedAmount(amount) {
  if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) {
    fail("CONSTRAINT_VIOLATION", "Amount must be a finite, non-negative number");
  }
  return amount;
}

function decimalParts(value) {
  const [mantissa, power = "0"] = String(value).split(/e/i);
  const [whole, fraction = ""] = mantissa.split(".");
  return [BigInt(whole + fraction), fraction.length - Number(power)];
}

export function addAmounts(left, right) {
  const [a, aScale] = decimalParts(left);
  const [b, bScale] = decimalParts(right);
  const scale = Math.max(aScale, bScale, 0);
  const total = a * 10n ** BigInt(scale - aScale) + b * 10n ** BigInt(scale - bScale);
  const digits = total.toString().padStart(scale + 1, "0");
  if (!scale) return digits;
  return `${digits.slice(0, -scale)}.${digits.slice(-scale)}`.replace(/0+$/, "").replace(/\.$/, "");
}

export function amountExceeds(left, right) {
  const [a, as] = decimalParts(left), [b, bs] = decimalParts(right);
  const scale = Math.max(as, bs);
  return a * 10n ** BigInt(scale - as) > b * 10n ** BigInt(scale - bs);
}

function stateful(claims) {
  return ["max_calls", "max_amount_usd", "rate_limit_per_min"].filter((key) => claims.constraints[key] != null);
}

function synchronous(result) {
  if (result && typeof result.then === "function") {
    // Prevent an unhandled rejection after the synchronous path has already
    // failed closed. Use asyncGuard to await the actual operation.
    Promise.resolve(result).catch(() => {});
    throw new TypeError("SwarmAuth requires synchronous tracker and decision callbacks");
  }
}

export class UsageTracker {
  constructor() { this.usage = new Map(); }
  checkAndRecord(claims, amount = 0) { this.checkAndRecordChain([claims], amount); }
  checkAndRecordChain(chain, amount = 0) {
    validatedAmount(amount);
    if (!chain.length || new Set(chain.map((claims) => claims.jti)).size !== chain.length) {
      fail("CONSTRAINT_VIOLATION", "Delegation token IDs must be distinct");
    }
    const now = Date.now() / 1000;
    if (chain.some((claims) => now >= claims.exp + RETENTION_AFTER_EXP_SECONDS)) fail("TOKEN_EXPIRED", "Token expired before usage reservation");
    for (const [id, entry] of this.usage) if (entry.expiresAt <= now) this.usage.delete(id);
    const pending = chain.map((claims) => {
      const previous = this.usage.get(claims.jti) ?? { calls: 0, amount: 0, timestamps: [], expiresAt: 0 };
      const timestamps = previous.timestamps.filter((time) => time >= now - 60);
      const limits = claims.constraints;
      if (limits.max_calls != null && previous.calls + 1 > limits.max_calls) fail("CONSTRAINT_VIOLATION", "Token call allowance exhausted");
      if (limits.max_amount_usd != null && amountExceeds(addAmounts(previous.amount, amount), limits.max_amount_usd)) fail("CONSTRAINT_VIOLATION", "Token budget exhausted");
      if (limits.rate_limit_per_min != null && timestamps.length + 1 > limits.rate_limit_per_min) fail("CONSTRAINT_VIOLATION", "Token rate allowance exhausted");
      return [claims.jti, { calls: previous.calls + 1, amount: addAmounts(previous.amount, amount),
        timestamps: [...timestamps, now], expiresAt: Math.max(previous.expiresAt, claims.exp + RETENTION_AFTER_EXP_SECONDS) }];
    });
    for (const [id, entry] of pending) this.usage.set(id, entry);
  }
}

export class InMemoryRevocationStore {
  constructor() { this.revoked = new Map(); }
  purge() {
    const now = Date.now() / 1000;
    for (const [id, until] of this.revoked) if (until <= now) this.revoked.delete(id);
  }
  revoke(jti, { expiresAt }) {
    this.purge();
    const until = expiresAt + RETENTION_AFTER_EXP_SECONDS;
    if (until > Date.now() / 1000) this.revoked.set(jti, Math.max(until, this.revoked.get(jti) ?? 0));
  }
  isRevoked(jti) { this.purge(); return this.revoked.has(jti); }
}

export function verifyAndCheck(token, options = {}) {
  let claims;
  try {
    claims = verify(token, options);
    if (options.requiredCapability && !capabilityCovered(options.requiredCapability, claims.capabilities)) {
      fail("CAPABILITY_VIOLATION", `Token does not grant capability '${options.requiredCapability}'`);
    }
    const allowed = claims.constraints.allowed_params;
    if (Object.keys(allowed).length && options.params == null) fail("CONSTRAINT_VIOLATION", "Token pins parameters but params are missing");
    for (const [key, expected] of Object.entries(allowed)) {
      if (!Object.hasOwn(options.params ?? {}, key) || !jsonEqual(options.params[key], expected)) {
        fail("CONSTRAINT_VIOLATION", `Parameter '${key}' does not match required value`);
      }
    }
    if (stateful(claims).length && !options.tracker) fail("CONSTRAINT_VIOLATION", "Token limits require a usage tracker");
    if (claims.constraints.shared_budget != null && !options.tracker?.supportsSharedBudgets) {
      fail("CONSTRAINT_VIOLATION", "Shared budget requires a budget-aware tracker");
    }
    if (claims.constraints.max_amount_usd != null && options.amount == null) {
      fail("CONSTRAINT_VIOLATION", "A budgeted call requires an explicit amount or amountArg");
    }
    const amount = options.amount == null ? 0 : validatedAmount(options.amount);
    if (options.tracker) {
      const parent = claims.prf ? parse(claims.prf).claims : null;
      if (parent && (stateful(parent).length || options.tracker.requiresChain)) {
        if (typeof options.tracker.checkAndRecordChain !== "function") fail("CONSTRAINT_VIOLATION", "Delegated limits require atomic checkAndRecordChain");
        synchronous(options.tracker.checkAndRecordChain([parent, claims], amount));
      } else synchronous(options.tracker.checkAndRecord(claims, amount));
    }
  } catch (error) {
    if (error instanceof SwarmAuthError && options.onDecision) synchronous(options.onDecision({
      decision: "denied", code: error.code, issuer: claims?.iss ?? null, audience: options.audience ?? null,
      capability: options.requiredCapability ?? null, tokenId: claims?.jti ?? null,
    }));
    throw error;
  }
  if (options.onDecision) synchronous(options.onDecision({ decision: "allowed", code: null,
    issuer: claims.iss, audience: claims.sub, capability: options.requiredCapability ?? null, tokenId: claims.jti }));
  return claims;
}

export function useToken(token, fn) {
  if (typeof token !== "string" || !token) throw new Error("token must be a non-empty string");
  return tokenContext.run(token, fn);
}

export function currentToken() {
  return tokenContext.getStore() ?? null;
}

export function guard(fn, options) {
  const audience = options.audience ?? options.capability;
  return (args = {}) => {
    const token = args.token || currentToken();
    if (!token) {
      if (options.onDecision) synchronous(options.onDecision({ decision: "denied", code: "CAPABILITY_VIOLATION",
        issuer: null, audience, capability: options.capability, tokenId: null }));
      fail("CAPABILITY_VIOLATION", "No JCT supplied");
    }
    const params = { ...args };
    delete params.token;
    verifyAndCheck(token, {
      publicKey: options.publicKey,
      registry: options.registry,
      revocationStore: options.revocationStore,
      onDecision: options.onDecision,
      audience,
      requiredCapability: options.capability,
      params,
      tracker: options.tracker,
      amount: options.amountArg ? params[options.amountArg] : undefined,
      now: options.now,
    });
    return fn(params);
  };
}
