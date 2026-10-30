/**
 * Capability token creation, parsing, and verification -- TypeScript
 * counterpart to swarmauth/token.py. See SPEC.md for the full protocol
 * specification; this module implements it, it does not redefine it.
 */
import { b64urlDecode, b64urlEncode } from "./base64.js";
import { canonicalJsonBytes, canonicalJsonString, type JsonValue } from "./canonicalJson.js";
import { KeyPair, verifySignature } from "./crypto.js";
import { KeyRegistry, type RevocationStore } from "./registry.js";
import {
  AudienceMismatchError,
  CapabilityViolationError,
  ConstraintViolationError,
  DelegationError,
  TokenRevokedError,
  InvalidSignatureError,
  MalformedTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
} from "./errors.js";

export const TOKEN_TYPE = "JCT";
export const ALG = "EdDSA";
export const MAX_TTL_SECONDS = 30;
export const MAX_LEEWAY_SECONDS = 2;

export interface Constraints {
  maxCalls?: number;
  maxAmountUsd?: number;
  rateLimitPerMin?: number;
  allowedParams?: Record<string, JsonValue>;
  sharedBudget?: string;
}

/** Constraints as carried on a parsed/issued token: unset fields are
 * explicitly `null` (matching the wire format), not simply absent. */
export interface NormalizedConstraints {
  maxCalls: number | null;
  maxAmountUsd: number | null;
  rateLimitPerMin: number | null;
  allowedParams: Record<string, JsonValue>;
  sharedBudget?: string;
}

export interface CapabilityClaims {
  iss: string;
  sub: string;
  capabilities: string[];
  constraints: NormalizedConstraints;
  iat: number;
  exp: number;
  jti: string;
  dlg?: string;
  prf?: string;
}

interface Header {
  alg: string;
  typ: string;
  kid: string;
}

function generateJti(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return b64urlEncode(bytes);
}

function normalizeConstraints(c?: Constraints): NormalizedConstraints {
  return {
    maxCalls: c?.maxCalls ?? null,
    maxAmountUsd: c?.maxAmountUsd ?? null,
    rateLimitPerMin: c?.rateLimitPerMin ?? null,
    allowedParams: c?.allowedParams ?? {},
    ...(c?.sharedBudget != null ? { sharedBudget: c.sharedBudget } : {}),
  };
}

// The wire format's field names and null-vs-absent handling must match
// swarmauth/token.py's Pydantic model_dump(mode="json") byte-for-byte
// (SPEC.md §3.3/§3.4): snake_case keys, nulls (not omission) for unset
// optional constraint fields.
function claimsToWireJson(claims: CapabilityClaims): JsonValue {
  return {
    iss: claims.iss,
    sub: claims.sub,
    capabilities: claims.capabilities,
    constraints: {
      max_calls: claims.constraints.maxCalls,
      max_amount_usd: claims.constraints.maxAmountUsd,
      rate_limit_per_min: claims.constraints.rateLimitPerMin,
      allowed_params: claims.constraints.allowedParams,
      ...(claims.constraints.sharedBudget != null ? { shared_budget: claims.constraints.sharedBudget } : {}),
    },
    iat: claims.iat,
    exp: claims.exp,
    jti: claims.jti,
    ...(claims.dlg ? { dlg: claims.dlg } : {}),
    ...(claims.prf ? { prf: claims.prf } : {}),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validJson(value: unknown): boolean {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
  if (Array.isArray(value)) return value.every(validJson);
  return isObject(value) && Object.values(value).every(validJson);
}

function wireJsonToClaims(payload: unknown): CapabilityClaims {
  if (!isObject(payload)) throw new MalformedTokenError("Token payload must be a JSON object");
  const p = payload;
  const fields = new Set(["iss", "sub", "capabilities", "iat", "exp", "jti", "constraints", "dlg", "prf"]);
  if (Object.keys(p).some((key) => !fields.has(key)) ||
      !["iss", "sub", "jti"].every((key) => typeof p[key] === "string" && (p[key] as string).length > 0) ||
      !Array.isArray(p.capabilities) || p.capabilities.length === 0 ||
      !p.capabilities.every((c) => typeof c === "string" && c.length > 0) ||
      !Number.isSafeInteger(p.iat) || !Number.isSafeInteger(p.exp) || (p.exp as number) <= (p.iat as number)) {
    throw new MalformedTokenError("Invalid claims schema");
  }
  for (const key of ["dlg", "prf"]) {
    if (p[key] != null && (typeof p[key] !== "string" || !(p[key] as string).length)) throw new MalformedTokenError(`Invalid ${key}`);
  }
  if (p.constraints === null) throw new MalformedTokenError("Invalid constraints");
  const c = p.constraints ?? {};
  const constraintFields = new Set(["max_calls", "max_amount_usd", "rate_limit_per_min", "allowed_params", "shared_budget"]);
  if (!isObject(c) || Object.keys(c).some((key) => !constraintFields.has(key))) throw new MalformedTokenError("Invalid constraints");
  for (const key of ["max_calls", "rate_limit_per_min"]) {
    if (c[key] != null && (!Number.isSafeInteger(c[key]) || (c[key] as number) < 1)) throw new MalformedTokenError(`Invalid ${key}`);
  }
  if (c.max_amount_usd != null && (typeof c.max_amount_usd !== "number" || !Number.isFinite(c.max_amount_usd) || c.max_amount_usd < 0)) {
    throw new MalformedTokenError("Invalid budget");
  }
  if (Object.hasOwn(c, "allowed_params") && (!isObject(c.allowed_params) || !validJson(c.allowed_params))) throw new MalformedTokenError("Invalid allowed_params");
  if (c.shared_budget != null) {
    const pins = isObject(c.allowed_params) ? c.allowed_params : {};
    if (typeof c.shared_budget !== "string" || !c.shared_budget || pins.budget_id !== c.shared_budget ||
        !Number.isSafeInteger(pins.amount_minor) || (pins.amount_minor as number) < 0 ||
        typeof pins.currency !== "string" || !/^[A-Z]{3}$/.test(pins.currency)) {
      throw new MalformedTokenError("Shared budget requires matching budget and monetary pins");
    }
  }
  return {
    iss: p.iss as string, sub: p.sub as string, jti: p.jti as string, capabilities: p.capabilities as string[],
    iat: p.iat as number, exp: p.exp as number,
    constraints: {
      maxCalls: c.max_calls as number | undefined ?? null,
      maxAmountUsd: c.max_amount_usd as number | undefined ?? null,
      rateLimitPerMin: c.rate_limit_per_min as number | undefined ?? null,
      allowedParams: c.allowed_params as Record<string, JsonValue> | undefined ?? {},
      ...(c.shared_budget != null ? { sharedBudget: c.shared_budget as string } : {}),
    },
    ...(p.dlg ? { dlg: p.dlg as string } : {}), ...(p.prf ? { prf: p.prf as string } : {}),
  };
}

export interface IssueOptions {
  issuerKeyPair: KeyPair;
  iss: string;
  sub: string;
  capabilities: string[];
  constraints?: Constraints;
  ttlSeconds?: number;
  dlg?: string;
}

/**
 * Create and sign a new capability token. `ttlSeconds` must be an integer from 1 to
 * MAX_TTL_SECONDS; a larger value is rejected, never silently shortened (SPEC §3).
 */
export async function issue(options: IssueOptions): Promise<string> {
  const ttlSeconds = options.ttlSeconds ?? 10;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
    throw new RangeError(`ttlSeconds must be an integer from 1 to ${MAX_TTL_SECONDS}`);
  }

  const now = Math.floor(Date.now() / 1000);
  const claims: CapabilityClaims = {
    iss: options.iss,
    sub: options.sub,
    capabilities: options.capabilities,
    constraints: normalizeConstraints(options.constraints),
    iat: now,
    exp: now + ttlSeconds,
    jti: generateJti(),
    ...(options.dlg ? { dlg: options.dlg } : {}),
  };
  return buildToken(options.issuerKeyPair, claims);
}

/** Internal: builds and signs a token from already-constructed claims.
 * Exported for use by conformance tooling that needs to pin iat/exp/jti
 * (real callers should use `issue`, which derives them safely). */
export async function buildToken(keyPair: KeyPair, claims: CapabilityClaims): Promise<string> {
  const header: Header = { alg: ALG, typ: TOKEN_TYPE, kid: keyPair.publicKeyId };
  const headerB64 = b64urlEncode(canonicalJsonBytes(header as unknown as JsonValue));
  const wire = claimsToWireJson(claims);
  wireJsonToClaims(wire);
  let payload = canonicalJsonString(wire);
  const amount = claims.constraints.maxAmountUsd;
  if (amount !== null && Number.isInteger(amount)) {
    payload = payload.replace(`"max_amount_usd":${canonicalJsonString(amount)}`, `"max_amount_usd":${amount.toFixed(1)}`);
  }
  const payloadB64 = b64urlEncode(new TextEncoder().encode(payload));
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = await keyPair.sign(signingInput);
  return `${headerB64}.${payloadB64}.${b64urlEncode(signature)}`;
}

export interface ParsedToken {
  header: Header;
  claims: CapabilityClaims;
  signingInput: Uint8Array;
}

/** Decode a token WITHOUT verifying its signature. */
export function parse(token: string): ParsedToken {
  if (typeof token !== "string") throw new MalformedTokenError("Token must be a string");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => !part)) {
    throw new MalformedTokenError(`Expected 3 dot-separated parts, got ${parts.length}`);
  }
  const [headerB64, payloadB64] = parts as [string, string, string];

  let header: Header;
  let payload: unknown;
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    header = JSON.parse(decoder.decode(b64urlDecode(headerB64)));
    payload = JSON.parse(decoder.decode(b64urlDecode(payloadB64)));
    b64urlDecode(parts[2]!);
  } catch {
    throw new MalformedTokenError("Token header/payload is not valid base64url JSON");
  }

  if (!isObject(header) || header.typ !== TOKEN_TYPE || header.alg !== ALG) {
    throw new MalformedTokenError(`Unsupported token header: ${JSON.stringify(header)}`);
  }

  const claims = wireJsonToClaims(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  return { header, claims, signingInput };
}

export interface VerifyOptions {
  issuerPublicKey?: Uint8Array;
  keyRegistry?: KeyRegistry;
  revocationStore?: RevocationStore;
  audience?: string;
  leewaySeconds?: number;
}

const sameKey = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((value, i) => value === b[i]);

async function verifyCore(token: string, options: VerifyOptions, holder = false): Promise<CapabilityClaims> {
  if (Boolean(options.issuerPublicKey) === Boolean(options.keyRegistry)) throw new TypeError("Pass exactly one of issuerPublicKey or keyRegistry");
  const leeway = options.leewaySeconds ?? 2;
  if (!Number.isInteger(leeway) || leeway < 0 || leeway > MAX_LEEWAY_SECONDS) throw new RangeError("leewaySeconds must be 0..2");
  const { header, claims, signingInput } = parse(token);
  let kid: Uint8Array;
  try {
    if (typeof header.kid !== "string" || !header.kid) throw new Error("missing kid");
    kid = b64urlDecode(header.kid);
    if (kid.length !== 32) throw new Error("invalid key length");
  } catch { throw new MalformedTokenError("Invalid kid"); }
  if (holder && !options.keyRegistry) throw new DelegationError("Delegation requires keyRegistry");
  const trusted = options.keyRegistry
    ? (holder ? options.keyRegistry.holderKeysFor(claims.iss) : options.keyRegistry.keysFor(claims.iss))
    : [options.issuerPublicKey!];
  if (!trusted.some((key) => sameKey(key, kid))) throw new InvalidSignatureError("Token kid does not match a trusted key");
  if (!await verifySignature(kid, signingInput, b64urlDecode(token.split(".")[2]!))) throw new InvalidSignatureError("Ed25519 signature verification failed");
  if (claims.exp - claims.iat > MAX_TTL_SECONDS) throw new TokenExpiredError("Token TTL exceeds maximum");
  const now = Math.floor(Date.now() / 1000);
  if (now < claims.iat - leeway) throw new TokenNotYetValidError("Token not yet valid");
  if (now > claims.exp + leeway) throw new TokenExpiredError("Token expired");
  if (await options.revocationStore?.isRevoked(claims.jti)) throw new TokenRevokedError("Token revoked");
  return claims;
}

function covered(capability: string, granted: string[]): boolean {
  return granted.some((item) => item === capability || (item.endsWith(":*") && capability.startsWith(item.slice(0, -1))));
}

function assertAttenuated(parent: CapabilityClaims, child: CapabilityClaims): void {
  if (parent.constraints.sharedBudget != null && child.constraints.sharedBudget !== parent.constraints.sharedBudget) {
    throw new DelegationError("Child drops or changes shared budget");
  }
  if (parent.prf || !parent.dlg || parent.dlg !== child.iss || child.dlg || child.jti === parent.jti || child.sub !== parent.sub ||
      child.iat < parent.iat || child.exp > parent.exp || !child.capabilities.every((cap) => covered(cap, parent.capabilities))) {
    throw new DelegationError("Invalid or widened delegation");
  }
  for (const key of ["maxCalls", "maxAmountUsd", "rateLimitPerMin"] as const) {
    const limit = parent.constraints[key];
    const requested = child.constraints[key];
    if (limit != null && (requested == null || !Number.isFinite(requested) || requested > limit)) throw new DelegationError(`Widened ${key}`);
  }
  for (const [key, expected] of Object.entries(parent.constraints.allowedParams)) {
    if (!Object.hasOwn(child.constraints.allowedParams, key) || !jsonEqual(child.constraints.allowedParams[key], expected)) throw new DelegationError(`Changed pin '${key}'`);
  }
}

/** Verify protocol claims and trust. Stateful call/budget enforcement belongs at the tool boundary. */
export async function verify(token: string, options: VerifyOptions): Promise<CapabilityClaims> {
  const preview = parse(token).claims;
  if (preview.prf && !options.keyRegistry) throw new DelegationError("Delegation requires keyRegistry");
  const claims = await verifyCore(token, options, Boolean(preview.prf));
  if (options.audience !== undefined && claims.sub !== options.audience) throw new AudienceMismatchError("Audience mismatch");
  if (claims.prf) {
    if (parse(claims.prf).claims.prf) throw new DelegationError("Only one delegation hop is allowed");
    assertAttenuated(await verifyCore(claims.prf, options), claims);
  } else if (claims.dlg) throw new DelegationError("A delegable token cannot be used directly");
  return claims;
}

export interface AttenuateOptions {
  issuerKeyPair: KeyPair;
  parent: string;
  iss: string;
  capabilities: string[];
  constraints?: Constraints;
  ttlSeconds?: number;
}

export async function attenuate(options: AttenuateOptions): Promise<string> {
  const ttl = options.ttlSeconds ?? 10;
  if (!Number.isInteger(ttl) || ttl <= 0 || ttl > MAX_TTL_SECONDS) throw new RangeError("ttlSeconds must be 1..30");
  const parent = parse(options.parent).claims;
  const now = Math.floor(Date.now() / 1000);
  if (parent.exp - parent.iat > MAX_TTL_SECONDS || now > parent.exp) throw new TokenExpiredError("Parent expired");
  if (now < parent.iat) throw new TokenNotYetValidError("Parent not yet valid");
  const child: CapabilityClaims = { iss: options.iss, sub: parent.sub, capabilities: options.capabilities,
    constraints: normalizeConstraints(options.constraints), iat: now, exp: now + ttl, jti: generateJti(), prf: options.parent };
  assertAttenuated(parent, child);
  return buildToken(options.issuerKeyPair, child);
}

function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) && Array.isArray(b)) return a.length === b.length && a.every((value, i) => jsonEqual(value, b[i]));
  return isObject(a) && isObject(b) && Object.keys(a).length === Object.keys(b).length &&
    Object.keys(a).every((key) => Object.hasOwn(b, key) && jsonEqual(a[key], b[key]));
}

/** Raise CapabilityViolationError unless `required` is granted.
 * Supports exact match or a `prefix:*` wildcard grant (e.g. `tool:*` grants `tool:read_invoice`). */
export function checkCapability(claims: CapabilityClaims, required: string): void {
  for (const granted of claims.capabilities) {
    if (granted === required) return;
    if (granted.endsWith(":*") && required.startsWith(granted.slice(0, -1))) return;
  }
  throw new CapabilityViolationError(`Token does not grant capability '${required}'`, required, claims.capabilities);
}

/** Enforce the constraints.allowedParams exact-match allowlist, if present. */
export function checkParams(claims: CapabilityClaims, params: Record<string, JsonValue>): void {
  const allowed = claims.constraints.allowedParams ?? {};
  for (const [key, expected] of Object.entries(allowed)) {
    if (!Object.hasOwn(params, key) || !jsonEqual(params[key], expected)) {
      throw new ConstraintViolationError(`Parameter '${key}'=${JSON.stringify(params[key])} does not match required value ${JSON.stringify(expected)}`, "allowed_params");
    }
  }
}
