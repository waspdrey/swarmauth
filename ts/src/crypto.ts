/**
 * Ed25519 key management, signing, and verification -- zero runtime
 * dependencies, using the standard Web Crypto API (`globalThis.crypto.subtle`),
 * available in Node.js 19+, browsers, Deno, Bun, and Cloudflare Workers alike.
 *
 * Web Crypto's `importKey` has no "raw" format for Ed25519 PRIVATE keys
 * (only public keys support "raw"; private keys need "pkcs8" or "jwk").
 * `PKCS8_ED25519_PREFIX` below is the fixed 16-byte PKCS8/DER envelope for
 * an Ed25519 private key -- fixed because Ed25519 (RFC 8410) has no
 * algorithm parameters, so everything but the raw 32-byte seed itself is a
 * constant. This lets `fromPrivateBytes` accept the same raw 32-byte seed
 * format as the reference Python SDK's `KeyPair.from_private_bytes`.
 */
import { b64urlDecode, b64urlEncode } from "./base64.js";

const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

const ED25519 = { name: "Ed25519" } as const;

export class KeyPair {
  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly publicKeyObj: CryptoKey,
    readonly publicBytes: Uint8Array,
  ) {}

  static async generate(): Promise<KeyPair> {
    const pair = (await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"])) as CryptoKeyPair;
    const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return new KeyPair(pair.privateKey, pair.publicKey, publicBytes);
  }

  /** `raw` must be exactly 32 bytes: the raw Ed25519 private seed, matching
   * the Python SDK's `KeyPair.private_bytes` / `from_private_bytes`. */
  static async fromPrivateBytes(raw: Uint8Array): Promise<KeyPair> {
    if (raw.length !== 32) {
      throw new RangeError(`Ed25519 private key seed must be 32 bytes, got ${raw.length}`);
    }
    const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
    pkcs8.set(PKCS8_ED25519_PREFIX, 0);
    pkcs8.set(raw, PKCS8_ED25519_PREFIX.length);

    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, ED25519, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    if (!jwk.x) throw new Error("failed to derive public key from imported Ed25519 private key");
    const publicBytes = b64urlDecode(jwk.x);
    const publicKeyObj = await crypto.subtle.importKey("raw", publicBytes as BufferSource, ED25519, true, ["verify"]);
    return new KeyPair(privateKey, publicKeyObj, publicBytes);
  }

  static async fromPublicBytes(raw: Uint8Array): Promise<CryptoKey> {
    return crypto.subtle.importKey("raw", raw as BufferSource, ED25519, true, ["verify"]);
  }

  /** Base64url-encoded public key -- usable as a stable key identifier (`kid`). */
  get publicKeyId(): string {
    return b64urlEncode(this.publicBytes);
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.sign(ED25519, this.privateKey, data as BufferSource));
  }
}

export async function verifySignature(publicKey: Uint8Array | CryptoKey, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  const key = publicKey instanceof Uint8Array ? await KeyPair.fromPublicBytes(publicKey) : publicKey;
  return crypto.subtle.verify(ED25519, key, signature as BufferSource, data as BufferSource);
}
