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
  InvalidSignatureError,
  MalformedTokenError,
  TokenExpiredError,
  TokenNotYetValidError,
} from "./errors.js";

export const TOKEN_TYPE = "JCT";
export const ALG = "EdDSA";
export const MAX_TTL_SECONDS = 300;

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
    },
    iat: claims.iat,
    exp: claims.exp,
    jti: claims.jti,
  };
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
  const c = (p.constraints ?? {}) as Record<string, unknown>;
  return {
    iss: p.iss,
    sub: p.sub,
    capabilities: p.capabilities as string[],
    constraints: {
      maxCalls: (c.max_calls as number | null | undefined) ?? null,
      maxAmountUsd: (c.max_amount_usd as number | null | undefined) ?? null,
      rateLimitPerMin: (c.rate_limit_per_min as number | null | undefined) ?? null,
      allowedParams: (c.allowed_params as Record<string, JsonValue> | undefined) ?? {},
    },
    iat: p.iat,
    exp: p.exp,
    jti: p.jti,
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

/** Create and sign a new capability token. `ttlSeconds` is clamped to MAX_TTL_SECONDS. */
export async function issue(options: IssueOptions): Promise<string> {
  const ttlSeconds = Math.min(options.ttlSeconds ?? 60, MAX_TTL_SECONDS);
  if (ttlSeconds <= 0) throw new RangeError("ttlSeconds must be positive");

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
  issuerPublicKey: Uint8Array;
  audience?: string;
  leewaySeconds?: number;
}

/** Fully verify a token: signature, TTL ceiling, expiry, and (optionally) audience.
 *
 * KeyRegistry (multi-issuer trust/rotation) and RevocationStore are not yet
 * ported to this reference implementation -- see ts/README.md's roadmap.
 * Only the single-issuer-key path (Python's `issuer_public_key=`) exists
 * here so far.
 */
export async function verify(token: string, options: VerifyOptions): Promise<CapabilityClaims> {
  const leewaySeconds = options.leewaySeconds ?? 2;
  const { header, claims, signingInput } = parse(token);
  const sigB64 = token.split(".")[2] as string;
  const signature = b64urlDecode(sigB64);

  const ok = await verifySignature(options.issuerPublicKey, signingInput, signature);
  if (!ok) throw new InvalidSignatureError("Ed25519 signature verification failed");

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
