/** Unpadded base64url, matching Python's
 * `base64.urlsafe_b64encode(data).rstrip(b"=")`. */

export function b64urlEncode(data: Uint8Array): string {
  let base64: string;
  if (typeof Buffer !== "undefined") {
    base64 = Buffer.from(data).toString("base64");
  } else {
    let binary = "";
    for (const byte of data) binary += String.fromCharCode(byte);
    base64 = btoa(binary);
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(data: string): Uint8Array {
  const padded = data.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (data.length % 4)) % 4);
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(padded, "base64"));
  }
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
