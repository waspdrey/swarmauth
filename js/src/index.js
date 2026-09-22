/**
 * SwarmAuth for JavaScript. Same JCT wire format as the Python reference SDK.
 * Verify tokens against spec/test-vectors/vectors.json before trusting a change.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { createPrivateKey, createPublicKey, randomBytes, sign, verify as verifyEd25519 } from "node:crypto";

export const MAX_TTL_SECONDS = 300;
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
  const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  return Buffer.from(text + pad, "base64url");
}

function formatAmount(value) {
  if (!Number.isFinite(value)) fail("CONSTRAINT_VIOLATION", "max_amount_usd must be finite");
  if (Number.isInteger(value)) return value.toFixed(1);
  return JSON.stringify(value);
}

function encode(value) {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) fail("MALFORMED_TOKEN", "non-finite number in claims");
    if (Number.isInteger(value)) return String(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(encode).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${encode(value[key])}`).join(",")}}`;
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
  return `{"allowed_params":${encode(allowed)},"max_amount_usd":${amount},"max_calls":${calls},"rate_limit_per_min":${rate}}`;
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

export function issue({ privateKey, iss, sub, capabilities, constraints, ttlSeconds = 60, dlg, iat, exp, jti }) {
  const seed = Buffer.from(privateKey);
  if (seed.length !== 32) throw new Error("privateKey must be a 32-byte Ed25519 seed");
  if (iat == null) requireTtl(ttlSeconds);
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
  return signToken(seed, claims);
}

function emptyConstraints(constraints = {}) {
  return {
    allowed_params: constraints.allowed_params ?? {},
    max_amount_usd: constraints.max_amount_usd ?? null,
    max_calls: constraints.max_calls ?? null,
    rate_limit_per_min: constraints.rate_limit_per_min ?? null,
  };
}

export function parse(token) {
  const parts = token.split(".");
  if (parts.length !== 3) fail("MALFORMED_TOKEN", `Expected 3 dot-separated parts, got ${parts.length}`);
  let header;
  let claims;
  try {
    header = JSON.parse(b64urlDecode(parts[0]).toString("utf8"));
    claims = JSON.parse(b64urlDecode(parts[1]).toString("utf8"));
  } catch {
    fail("MALFORMED_TOKEN", "Token header/payload is not valid base64url JSON");
  }
  if (header.typ !== TOKEN_TYPE || header.alg !== ALG) fail("MALFORMED_TOKEN", "Unsupported token header");
  if (!claims.iss || !claims.sub || !Array.isArray(claims.capabilities) || claims.capabilities.length === 0) {
    fail("MALFORMED_TOKEN", "Invalid claims schema");
  }
  return { header, claims, signingInput: `${parts[0]}.${parts[1]}` };
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
  for (const name of ["max_calls", "max_amount_usd", "rate_limit_per_min"]) {
    if (limitIsWider(childConstraints[name], parentConstraints[name])) {
      fail("DELEGATION_VIOLATION", `Attenuated ${name} widens the parent limit`);
    }
  }
  for (const [key, expected] of Object.entries(parentConstraints.allowed_params ?? {})) {
    if ((childConstraints.allowed_params ?? {})[key] !== expected) {
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

export function attenuate({ privateKey, parent, iss, capabilities, constraints, ttlSeconds = 60 }) {
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

  keysFor(iss) {
    const keys = this.roots.get(iss);
    if (!keys?.length) fail("UNKNOWN_ISSUER", `No trusted key registered for issuer '${iss}'`);
    return keys;
  }

  holderKeysFor(iss) {
    const keys = this.holders.get(iss);
    if (!keys?.length) fail("UNKNOWN_ISSUER", `No holder key registered for delegate '${iss}'`);
    return keys;
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
    if (!this.iss || !this.sub || this.capabilities.length === 0) throw new Error("Grant requires iss, sub, and capabilities");
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
    if ((constraints.allowed_params ?? {})[key] !== expected) return `Issued token does not pin '${key}'`;
  }
  if (dlg != null && !grant.delegates.includes(dlg)) return `Grant does not allow delegation to '${dlg}'`;
  return null;
}

export function verifyAndCheck(token, options = {}) {
  const claims = verify(token, options);
  if (options.requiredCapability && !capabilityCovered(options.requiredCapability, claims.capabilities)) {
    fail("CAPABILITY_VIOLATION", `Token does not grant capability '${options.requiredCapability}'`);
  }
  const allowed = claims.constraints?.allowed_params ?? {};
  if (options.params) {
    for (const [key, expected] of Object.entries(allowed)) {
      if (options.params[key] !== expected) {
        fail("CONSTRAINT_VIOLATION", `Parameter '${key}' does not match required value`);
      }
    }
  }
  const stateful = ["max_calls", "max_amount_usd", "rate_limit_per_min"].filter((name) => claims.constraints?.[name] != null);
  if (stateful.length && !options.tracker) {
    fail("CONSTRAINT_VIOLATION", `Token declares ${stateful.join(", ")} but no usage tracker was provided`);
  }
  options.tracker?.checkAndRecord(claims, options.amount ?? 0);
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
    if (!token) fail("CAPABILITY_VIOLATION", "No JCT supplied");
    const params = { ...args };
    delete params.token;
    verifyAndCheck(token, {
      publicKey: options.publicKey,
      registry: options.registry,
      audience,
      requiredCapability: options.capability,
      params,
      tracker: options.tracker,
      amount: options.amountArg ? params[options.amountArg] : 0,
      now: options.now,
    });
    return fn(params);
  };
}
