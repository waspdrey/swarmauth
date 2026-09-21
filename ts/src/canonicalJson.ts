/**
 * Deterministic JSON encoding matching swarmauth/token.py's `_canonical_json`
 * exactly: `json.dumps(obj, sort_keys=True, separators=(",", ":"),
 * ensure_ascii=True)`. Every signature is over these exact bytes (SPEC.md
 * §3.4), so any deviation here breaks cross-implementation verification.
 *
 * `JSON.stringify` alone does not match Python's `json.dumps` on two axes:
 * it does not sort object keys, and it does not escape non-ASCII characters
 * (Python's `ensure_ascii=True` does). Both are handled explicitly below.
 * Escaping proceeds per UTF-16 code unit, which -- since JS strings are
 * natively UTF-16 -- reproduces CPython's surrogate-pair `\uXXXX\uXXXX`
 * escaping of non-BMP characters for free.
 */

const SINGLE_CHAR_ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\b": "\\b",
  "\f": "\\f",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
};

function encodeString(value: string): string {
  let out = '"';
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    const special = SINGLE_CHAR_ESCAPES[ch];
    if (special !== undefined) {
      out += special;
    } else if (code < 0x20 || code > 0x7e) {
      out += "\\u" + code.toString(16).padStart(4, "0");
    } else {
      out += ch;
    }
  }
  return out + '"';
}

function encodeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError(`Cannot canonicalize non-finite number: ${value}`);
  }
  return String(value);
}

/** JSON value type accepted for canonicalization: the subset produced by
 * JSON.parse / used to build CapabilityClaims payloads. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export function canonicalJsonString(value: JsonValue): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return encodeNumber(value);
  if (typeof value === "string") return encodeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJsonString).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${encodeString(key)}:${canonicalJsonString((value as Record<string, JsonValue>)[key] as JsonValue)}`);
  return "{" + parts.join(",") + "}";
}

export function canonicalJsonBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(canonicalJsonString(value));
}
