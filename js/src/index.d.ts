export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface Constraints {
  max_calls?: number | null;
  max_amount_usd?: number | null;
  rate_limit_per_min?: number | null;
  allowed_params?: Record<string, Json>;
  shared_budget?: string | null;
}
export interface Claims {
  iss: string; sub: string; capabilities: string[]; iat: number; exp: number; jti: string;
  constraints: Required<Omit<Constraints, "shared_budget">> & Pick<Constraints, "shared_budget">; dlg?: string; prf?: string;
}
export interface AuthorizationEvent {
  decision: "allowed" | "denied"; code: string | null; issuer: string | null;
  audience: string | null; capability: string | null; tokenId: string | null;
}
export class SwarmAuthError extends Error { code: string; constructor(code: string, message: string); }
export const MAX_TTL_SECONDS: number;
export const MAX_LEEWAY_SECONDS: number;
export const RETENTION_AFTER_EXP_SECONDS: number;
export function b64urlEncode(data: Uint8Array): string;
export function b64urlDecode(value: string): Uint8Array;
export function canonicalJson(value: Json): string;
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array;
export interface IssueRequest {
  privateKey: Uint8Array; iss: string; sub: string; capabilities: string[];
  constraints?: Constraints; ttlSeconds?: number; dlg?: string;
  iat?: number; exp?: number; jti?: string;
}
export function issue(request: IssueRequest): string;
export function parse(token: string): { header: { alg: string; typ: string; kid: string }; claims: Claims; signingInput: string };
export interface AttenuateRequest {
  privateKey: Uint8Array; parent: string; iss: string; capabilities: string[];
  constraints?: Constraints; ttlSeconds?: number;
}
export function attenuate(request: AttenuateRequest): string;
export function capabilityCovered(capability: string, granted: string[]): boolean;
export function checkLifetime(request: { iat: number; exp: number; leewaySeconds?: number; now: number }): void;
export class KeyRegistry {
  register(iss: string, key: Uint8Array, options?: { rotate?: boolean }): void;
  registerHolder(iss: string, key: Uint8Array): void;
  revoke(iss: string, key: Uint8Array): void;
  revokeHolder(iss: string, key: Uint8Array): void;
  revokeIssuer(iss: string): void;
  keysFor(iss: string): Uint8Array[];
  holderKeysFor(iss: string): Uint8Array[];
}
export interface GrantFields {
  iss: string; sub: string; capabilities: string[]; maxTtlSeconds?: number; maxCalls?: number | null;
  maxAmountUsd?: number | null; rateLimitPerMin?: number | null; delegates?: string[]; pinnedParams?: Record<string, Json>;
}
export class Grant { constructor(fields: GrantFields); }
export type PolicyRequest = Omit<IssueRequest, "privateKey" | "iat" | "exp" | "jti">;
export class IssuerPolicy { constructor(grants?: Grant[]); check(request: PolicyRequest): void; }
export class TokenIssuer {
  constructor(privateKey: Uint8Array, options: { policy: IssuerPolicy });
  issue(request: PolicyRequest): string;
  attenuate(request: Omit<AttenuateRequest, "privateKey">): string;
}
export interface Tracker {
  supportsSharedBudgets?: boolean;
  requiresChain?: boolean;
  checkAndRecord(claims: Claims, amount?: number): void;
  checkAndRecordChain?(chain: Claims[], amount?: number): void;
}
export interface AsyncTracker {
  supportsSharedBudgets?: boolean;
  requiresChain?: boolean;
  checkAndRecord(claims: Claims, amount?: number): void | Promise<void>;
  checkAndRecordChain?(chain: Claims[], amount?: number): void | Promise<void>;
}
export interface RevocationStore { isRevoked(jti: string): boolean; }
export interface AsyncRevocationStore { isRevoked(jti: string): boolean | Promise<boolean>; }
export class InMemoryRevocationStore implements RevocationStore {
  revoke(jti: string, options: { expiresAt: number }): void;
  isRevoked(jti: string): boolean;
}
export class UsageTracker implements Tracker {
  checkAndRecord(claims: Claims, amount?: number): void;
  checkAndRecordChain(chain: Claims[], amount?: number): void;
}
export interface VerifyOptions {
  publicKey?: Uint8Array; registry?: KeyRegistry; audience?: string; leewaySeconds?: number; now?: number;
  revocationStore?: RevocationStore;
}
export interface EnforcementOptions extends VerifyOptions {
  requiredCapability?: string; amount?: number; params?: Record<string, Json>; tracker?: Tracker;
  onDecision?: (event: AuthorizationEvent) => void;
}
export interface AsyncEnforcementOptions extends Omit<EnforcementOptions, "tracker" | "onDecision" | "revocationStore"> {
  tracker?: AsyncTracker; revocationStore?: AsyncRevocationStore;
  onDecision?: (event: AuthorizationEvent) => void | Promise<void>;
}
export function verify(token: string, options: VerifyOptions): Claims;
export function verifyAndCheck(token: string, options: EnforcementOptions): Claims;
export function asyncVerifyAndCheck(token: string, options: AsyncEnforcementOptions): Promise<Claims>;
export function useToken<T>(token: string, fn: () => T): T;
export function currentToken(): string | null;
export interface GuardOptions extends EnforcementOptions { capability: string; amountArg?: string; }
export interface AsyncGuardOptions extends AsyncEnforcementOptions { capability: string; amountArg?: string; }
export function guard<T extends object, R>(fn: (args: T) => R, options: GuardOptions): (args?: T & { token?: string }) => R;
export function asyncGuard<T extends object, R>(fn: (args: T) => R, options: AsyncGuardOptions): (args?: T & { token?: string }) => Promise<Awaited<R>>;
export function addAmounts(left: number | string, right: number | string): string;
export function amountExceeds(left: number | string, right: number | string): boolean;
export interface BudgetRuleFields {
  id: string; issuers: readonly string[]; currency: string; maxAmountMinor: number; expiresAt: number; maxCalls?: number | null;
}
export class BudgetRule implements BudgetRuleFields {
  constructor(fields: BudgetRuleFields);
  readonly id: string; readonly issuers: readonly string[]; readonly currency: string;
  readonly maxAmountMinor: number; readonly expiresAt: number; readonly maxCalls: number | null;
}
export class BudgetUsageTracker implements Tracker {
  constructor(rules?: BudgetRuleFields[], options?: { requireBudget?: boolean });
  readonly requiresChain: true;
  checkAndRecord(claims: Claims, amount?: number): void;
  checkAndRecordChain(chain: Claims[], amount?: number): void;
}
export interface RedisConnection {
  watch(keys: string[]): Promise<unknown>; unwatch(): Promise<unknown>;
  mGet(keys: string[]): Promise<(string | null)[]>;
  multi(): { set(key: string, value: string, options: { PX: number }): unknown; exec(): Promise<unknown> };
}
export interface RedisPool { execute<T>(callback: (client: RedisConnection) => Promise<T>): Promise<T>; }
export class RedisUsageTracker implements AsyncTracker {
  constructor(pool: RedisPool, options?: { rules?: BudgetRuleFields[]; requireBudget?: boolean; keyPrefix?: string; maxRetries?: number });
  readonly requiresChain: true;
  checkAndRecord(claims: Claims, amount?: number): Promise<void>;
  checkAndRecordChain(chain: Claims[], amount?: number): Promise<void>;
}
export function tokenContextMiddleware(options?: { maxTokenBytes?: number }): (
  req: { rawHeaders: string[] },
  res: { setHeader(name: string, value: string): unknown; status(code: number): { json(body: object): unknown } },
  next: () => void,
) => void;
