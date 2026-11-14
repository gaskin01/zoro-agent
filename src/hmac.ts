import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * HMAC-SHA256 over the RAW request/response body.
 *
 * The platform signs every inbound request with the agent secret and puts the
 * signature in the `x-agent-games-signature` header. We verify it BEFORE
 * parsing JSON, and sign every response the same way.
 *
 * Header formats accepted on verify (the spec does not pin one down):
 *   - 64 lowercase hex chars (optionally prefixed with "0x" or "sha256=")
 *   - base64
 * We sign responses as lowercase hex without a prefix (the most common form).
 */

export function signBody(secret: string, body: Buffer | string): string {
  const buf = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return createHmac("sha256", secret).update(buf).digest("hex");
}

function decodeSignature(header: string): Buffer | null {
  let h = header.trim();
  if (h.toLowerCase().startsWith("sha256=")) h = h.slice("sha256=".length);
  if (h.toLowerCase().startsWith("0x")) h = h.slice(2);
  // Hex (64 chars = 32 bytes) is the expected form.
  if (/^[0-9a-fA-F]{64}$/.test(h)) return Buffer.from(h, "hex");
  // Fall back to base64.
  try {
    const b = Buffer.from(h, "base64");
    if (b.length === 32) return b;
  } catch {
    // ignore
  }
  return null;
}

export function verifySignature(secret: string, body: Buffer, header: string | undefined): boolean {
  if (!header) return false;
  const expected = createHmac("sha256", secret).update(body).digest();
  const got = decodeSignature(header);
  if (!got || got.length !== expected.length) return false;
  return timingSafeEqual(got, expected);
}
