import { UnknownIssuerError } from "./errors.js";

const sameKey = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((value, i) => value === b[i]);

/** Locally configured trust; holder keys never authorize fresh root grants. */
export class KeyRegistry {
  private roots = new Map<string, Uint8Array[]>();
  private holders = new Map<string, Uint8Array[]>();

  register(iss: string, key: Uint8Array, options: { rotate?: boolean } = {}): void {
    const previous = options.rotate ? this.roots.get(iss) ?? [] : [];
    this.roots.set(iss, [key.slice(), ...previous.filter((item) => !sameKey(item, key))]);
  }
  registerHolder(iss: string, key: Uint8Array): void {
    this.holders.set(iss, [key.slice(), ...(this.holders.get(iss) ?? []).filter((item) => !sameKey(item, key))]);
  }
  keysFor(iss: string): Uint8Array[] { return this.get(this.roots, iss); }
  holderKeysFor(iss: string): Uint8Array[] { return this.get(this.holders, iss); }
  revoke(iss: string, key: Uint8Array): void { this.remove(this.roots, iss, key); }
  revokeHolder(iss: string, key: Uint8Array): void { this.remove(this.holders, iss, key); }
  revokeIssuer(iss: string): void { this.roots.delete(iss); this.holders.delete(iss); }

  private get(map: Map<string, Uint8Array[]>, iss: string): Uint8Array[] {
    const keys = map.get(iss);
    if (!keys?.length) throw new UnknownIssuerError(`No trusted key registered for '${iss}'`);
    return keys.map((key) => key.slice());
  }
  private remove(map: Map<string, Uint8Array[]>, iss: string, key: Uint8Array): void {
    const remaining = (map.get(iss) ?? []).filter((item) => !sameKey(item, key));
    if (remaining.length) map.set(iss, remaining);
    else map.delete(iss);
  }
}

export interface RevocationStore {
  isRevoked(jti: string): boolean | Promise<boolean>;
}

/** Retain through exp + 2 seconds, including the entire final accepted second. */
export class InMemoryRevocationStore implements RevocationStore {
  private revoked = new Map<string, number>();
  revoke(jti: string, options: { expiresAt: number }): void {
    this.purge();
    const until = options.expiresAt + 3;
    if (until > Date.now() / 1000) this.revoked.set(jti, Math.max(until, this.revoked.get(jti) ?? 0));
  }
  isRevoked(jti: string): boolean { this.purge(); return this.revoked.has(jti); }
  private purge(): void {
    for (const [jti, until] of this.revoked) if (until <= Date.now() / 1000) this.revoked.delete(jti);
  }
}
