/**
 * Capability token creation, parsing, and verification -- TypeScript
 * counterpart to swarmauth/token.py. See SPEC.md for the full protocol
 * specification; this module implements it, it does not redefine it.
 */
import { b64urlDecode, b64urlEncode } from "./base64.js";
import { canonicalJsonBytes, type JsonValue } from "./canonicalJson.js";
import { KeyPair, verifySignature } from "./crypto.js";
import {
  AudienceMismatchError,
  CapabilityViolationError,
  ConstraintViolationError,
  DelegationError,
  InvalidSignatureError,
  MalformedTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
  UnknownIssuerError,
} from "./errors.js";

export const TOKEN_TYPE = "JCT";
export const ALG = "EdDSA";
export const MAX_TTL_SECONDS = 30;

export interface Constraints {
  maxCalls?: number;
  maxAmountUsd?: number;
  rateLimitPerMin?: number;
  allowedParams?: Record<string, JsonValue>;
}

/** Constraints as carried on a parsed/issued token: unset fields are
 * explicitly `null` (matching the wire format), not simply absent. */
export interface NormalizedConstraints {
  maxCalls: number | null;
  maxAmountUsd: number | null;
  rateLimitPerMin: number | null;
  allowedParams: Record<string, JsonValue>;
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
  for (const [name, value] of Object.entries(c ?? {})) {
    if (value === undefined) continue;
    if (name === "maxAmountUsd") {
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
        throw new RangeError("maxAmountUsd must be a finite, non-negative number");
      }
    } else if (name === "maxCalls" || name === "rateLimitPerMin") {
      if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
        throw new RangeError(`${name} must be a non-negative integer`);
      }
    }
  }
  return {
    maxCalls: c?.maxCalls ?? null,
    maxAmountUsd: c?.maxAmountUsd ?? null,
    rateLimitPerMin: c?.rateLimitPerMin ?? null,
    allowedParams: c?.allowedParams ?? {},
  };
}

// The wire format's field names and null-vs-absent handling must match
// swarmauth/token.py's Pydantic model_dump(mode="json") byte-for-byte
// (SPEC.md §3.3/§3.4): snake_case keys, nulls (not omission) for unset
// optional constraint fields.
function claimsToWireJson(claims: CapabilityClaims): JsonValue {
  const wire: Record<string, JsonValue> = {
    iss: claims.iss,
    sub: claims.sub,
    capabilities: claims.capabilities,
    constraints: {
      max_calls: claims.constraints.maxCalls,
      max_amount_usd: claims.constraints.maxAmountUsd,
      rate_limit_per_min: claims.constraints.rateLimitPerMin,
      allowed_params: claims.constraints.allowedParams,
    },
    iat: claims.iat,
    exp: claims.exp,
    jti: claims.jti,
  };
  if (claims.dlg !== undefined) wire.dlg = claims.dlg;
  if (claims.prf !== undefined) wire.prf = claims.prf;
  return wire;
}

function wireJsonToClaims(payload: unknown): CapabilityClaims {
  if (typeof payload !== "object" || payload === null) {
    throw new MalformedTokenError("Token payload is not a JSON object");
  }
  const p = payload as Record<string, unknown>;
  const required = ["iss", "sub", "capabilities", "iat", "exp", "jti"] as const;
  for (const key of required) {
    if (!(key in p)) throw new MalformedTokenError(`Token payload missing required claim '${key}'`);
  }
  if (typeof p.iss !== "string" || typeof p.sub !== "string" || typeof p.jti !== "string") {
    throw new MalformedTokenError("Token payload has a wrongly-typed string claim");
  }
  if (!Array.isArray(p.capabilities) || p.capabilities.length === 0 || !p.capabilities.every((c) => typeof c === "string" && c.length > 0)) {
    throw new MalformedTokenError("'capabilities' must be a non-empty array of non-empty strings");
  }
  if (typeof p.iat !== "number" || typeof p.exp !== "number") {
    throw new MalformedTokenError("'iat'/'exp' must be numbers");
  }
  for (const key of ["dlg", "prf"] as const) {
    if (p[key] !== undefined && (typeof p[key] !== "string" || p[key].length === 0)) {
      throw new MalformedTokenError(`'${key}' must be a non-empty string when present`);
    }
  }
  const c = (p.constraints ?? {}) as Record<string, unknown>;
  const constraints = {
    maxCalls: (c.max_calls as number | null | undefined) ?? null,
    maxAmountUsd: (c.max_amount_usd as number | null | undefined) ?? null,
    rateLimitPerMin: (c.rate_limit_per_min as number | null | undefined) ?? null,
    allowedParams: (c.allowed_params as Record<string, JsonValue> | undefined) ?? {},
  };
  normalizeConstraints({ maxCalls: constraints.maxCalls ?? undefined, maxAmountUsd: constraints.maxAmountUsd ?? undefined, rateLimitPerMin: constraints.rateLimitPerMin ?? undefined });
  return {
    iss: p.iss,
    sub: p.sub,
    capabilities: p.capabilities as string[],
    constraints,
    iat: p.iat,
    exp: p.exp,
    jti: p.jti,
    ...(p.dlg === undefined ? {} : { dlg: p.dlg as string }),
    ...(p.prf === undefined ? {} : { prf: p.prf as string }),
  };
}

export interface IssueOptions {
  issuerKeyPair: KeyPair;
  iss: string;
  sub: string;
  capabilities: string[];
  constraints?: Constraints;
  ttlSeconds?: number;
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
  };
  return buildToken(options.issuerKeyPair, claims);
}

/** Internal: builds and signs a token from already-constructed claims.
 * Exported for use by conformance tooling that needs to pin iat/exp/jti
 * (real callers should use `issue`, which derives them safely). */
export async function buildToken(keyPair: KeyPair, claims: CapabilityClaims): Promise<string> {
  const header: Header = { alg: ALG, typ: TOKEN_TYPE, kid: keyPair.publicKeyId };
  const headerB64 = b64urlEncode(canonicalJsonBytes(header as unknown as JsonValue));
  const payloadB64 = b64urlEncode(canonicalJsonBytes(claimsToWireJson(claims)));
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
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new MalformedTokenError(`Expected 3 dot-separated parts, got ${parts.length}`);
  }
  const [headerB64, payloadB64] = parts as [string, string, string];

  let header: Header;
  let payload: unknown;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64)));
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
  } catch {
    throw new MalformedTokenError("Token header/payload is not valid base64url JSON");
  }

  if (header.typ !== TOKEN_TYPE || header.alg !== ALG) {
    throw new MalformedTokenError(`Unsupported token header: ${JSON.stringify(header)}`);
  }

  const claims = wireJsonToClaims(payload);
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  return { header, claims, signingInput };
}

export interface VerifyOptions {
  issuerPublicKey?: Uint8Array;
  registry?: KeyRegistry;
  audience?: string;
  leewaySeconds?: number;
}

export class KeyRegistry {
  private readonly roots = new Map<string, Uint8Array[]>();
  private readonly holders = new Map<string, Uint8Array[]>();

  register(iss: string, publicKey: Uint8Array): void {
    this.roots.set(iss, [new Uint8Array(publicKey)]);
  }

  registerHolder(iss: string, publicKey: Uint8Array): void {
    this.holders.set(iss, [new Uint8Array(publicKey)]);
  }

  keysFor(iss: string, holder = false): Uint8Array[] {
    const keys = (holder ? this.holders : this.roots).get(iss);
    if (!keys?.length) throw new UnknownIssuerError(`No trusted key registered for '${iss}'`);
    return keys;
  }
}

function sameKey(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function kidBytes(header: Header): Uint8Array {
  if (typeof header.kid !== "string" || header.kid.length === 0) {
    throw new MalformedTokenError("Token header is missing kid");
  }
  const raw = b64urlDecode(header.kid);
  if (raw.length !== 32) throw new MalformedTokenError("Token kid is not a 32-byte Ed25519 public key");
  return raw;
}

async function verifySignatureAndKid(
  header: Header,
  claims: CapabilityClaims,
  signingInput: Uint8Array,
  signature: Uint8Array,
  options: VerifyOptions,
  holder: boolean,
): Promise<void> {
  const kid = kidBytes(header);
  if (options.registry) {
    const trusted = options.registry.keysFor(claims.iss, holder);
    if (!trusted.some((key) => sameKey(key, kid))) {
      throw new InvalidSignatureError(`Token kid is not a trusted key for issuer '${claims.iss}'`);
    }
    if (!(await verifySignature(kid, signingInput, signature))) {
      throw new InvalidSignatureError("Ed25519 signature verification failed");
    }
    return;
  }
  if (holder) throw new DelegationError("Delegated tokens require a key registry containing the root issuer and delegate");
  if (!options.issuerPublicKey) throw new TypeError("Pass exactly one of issuerPublicKey or registry");
  if (!sameKey(options.issuerPublicKey, kid)) {
    throw new InvalidSignatureError("Token kid does not match the trusted issuer public key");
  }
  if (!(await verifySignature(options.issuerPublicKey, signingInput, signature))) {
    throw new InvalidSignatureError("Ed25519 signature verification failed");
  }
}

function capabilityCovered(capability: string, granted: string[]): boolean {
  return granted.some((item) => item === capability || (item.endsWith(":*") && capability.startsWith(item.slice(0, -1))));
}

function limitIsWider(child: number | null, parent: number | null): boolean {
  return parent !== null && (child === null || child > parent);
}

function assertAttenuated(parent: CapabilityClaims, child: CapabilityClaims): void {
  if (parent.prf || !parent.dlg || parent.dlg !== child.iss) throw new DelegationError("Parent token does not authorize this delegate");
  if (child.dlg || child.sub !== parent.sub || child.iat < parent.iat || child.exp > parent.exp) {
    throw new DelegationError("Attenuated token widens or changes the parent grant");
  }
  if (child.capabilities.some((capability) => !capabilityCovered(capability, parent.capabilities))) {
    throw new DelegationError("Attenuated token capability exceeds the parent grant");
  }
  for (const name of ["maxCalls", "maxAmountUsd", "rateLimitPerMin"] as const) {
    if (limitIsWider(child.constraints[name], parent.constraints[name])) {
      throw new DelegationError(`Attenuated ${name} widens the parent limit`);
    }
  }
  for (const [key, expected] of Object.entries(parent.constraints.allowedParams)) {
    if (JSON.stringify(child.constraints.allowedParams[key]) !== JSON.stringify(expected)) {
      throw new DelegationError(`Attenuated token drops or changes pinned parameter '${key}'`);
    }
  }
}

/** Fully verify a token: signature, TTL ceiling, expiry, and (optionally) audience.
 *
 * Supports either a single trusted issuer key or a KeyRegistry for root and
 * delegated holder keys. RevocationStore remains outside this reference
 * implementation; callers should enforce revocation before execution.
 */
export async function verify(token: string, options: VerifyOptions): Promise<CapabilityClaims> {
  if ((options.issuerPublicKey === undefined) === (options.registry === undefined)) {
    throw new TypeError("Pass exactly one of issuerPublicKey or registry");
  }
  const leewaySeconds = options.leewaySeconds ?? 2;
  const preview = parse(token);
  const { header, claims, signingInput } = preview;
  const sigB64 = token.split(".")[2] as string;
  const signature = b64urlDecode(sigB64);

  if (claims.prf && !options.registry) {
    throw new DelegationError("Delegated tokens require a key registry containing the root issuer and delegate");
  }
  await verifySignatureAndKid(header, claims, signingInput, signature, options, Boolean(claims.prf));

  if (claims.exp - claims.iat > MAX_TTL_SECONDS) {
    throw new TokenExpiredError(`Token TTL ${claims.exp - claims.iat}s exceeds max ${MAX_TTL_SECONDS}s`);
  }

  const now = Math.floor(Date.now() / 1000);
  if (now < claims.iat - leewaySeconds) {
    throw new TokenNotYetValidError(`Token not valid until ${claims.iat}, now is ${now}`);
  }
  if (now > claims.exp + leewaySeconds) {
    throw new TokenExpiredError(`Token expired at ${claims.exp}, now is ${now}`);
  }

  if (options.audience !== undefined && claims.sub !== options.audience) {
    throw new AudienceMismatchError(`Token audience '${claims.sub}' does not match '${options.audience}'`);
  }

  if (claims.prf) {
    const parentParsed = parse(claims.prf);
    if (parentParsed.claims.prf) throw new DelegationError("Delegation chains are limited to one hop");
    const parentSignature = b64urlDecode(claims.prf.split(".")[2] as string);
    await verifySignatureAndKid(
      parentParsed.header,
      parentParsed.claims,
      parentParsed.signingInput,
      parentSignature,
      options,
      false,
    );
    if (parentParsed.claims.exp - parentParsed.claims.iat > MAX_TTL_SECONDS) {
      throw new TokenExpiredError("Parent token TTL exceeds maximum");
    }
    assertAttenuated(parentParsed.claims, claims);
  } else if (claims.dlg) {
    throw new DelegationError("A delegable token cannot be presented as an execution credential");
  }

  return claims;
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
    if (JSON.stringify(params[key]) !== JSON.stringify(expected)) {
      throw new ConstraintViolationError(`Parameter '${key}'=${JSON.stringify(params[key])} does not match required value ${JSON.stringify(expected)}`, "allowed_params");
    }
  }
}
