import { createHmac, timingSafeEqual } from "node:crypto";
import { assertSecret, assertTolerance, type Body, type VerifyResult } from "./sign.js";

/**
 * Verifies a `Stripe-Signature` header by the manual algorithm in Stripe's docs:
 * https://docs.stripe.com/webhooks#verify-manually
 *
 *  1. Split the header on `,`, then each element on `=`: `t` is the timestamp (seconds), `v1` the
 *     signature(s). Other schemes (such as the test-only `v0`) are ignored, which prevents a
 *     downgrade to a weaker scheme.
 *  2. signed_payload = `${t}.${rawBody}`
 *  3. expected = HMAC-SHA256(key = the endpoint's `whsec_...` secret, message = signed_payload), hex
 *  4. Compare to every `v1` in constant time; then check |now - t| against the tolerance
 *     (Stripe's libraries default to 5 minutes).
 *
 * NOT run against live Stripe. The tests build their vectors from the algorithm above.
 * `body` must be the raw request body: any re-serialisation breaks the signature.
 */
export function verifyStripeSignature(params: {
  /** The `whsec_...` endpoint secret, or two during a "roll secret" overlap. Used as-is (UTF-8 bytes). */
  secret: string | readonly string[];
  /** Value of the `Stripe-Signature` header. */
  header: string | null | undefined;
  body: Body;
  /** Seconds; default 300. Must be positive: 0 would disable the recency check. */
  toleranceSeconds?: number;
  /** Epoch milliseconds; injectable for tests. */
  nowMs?: number;
}): VerifyResult {
  const secrets = typeof params.secret === "string" ? [params.secret] : [...params.secret];
  if (secrets.length === 0) throw new TypeError("at least one webhook secret is required");
  for (const s of secrets) assertSecret(s);
  const toleranceSeconds = params.toleranceSeconds ?? 300;
  assertTolerance(toleranceSeconds, "seconds");

  if (!params.header) return { ok: false, reason: "missing_header" };

  let t: string | undefined;
  let tCount = 0;
  const v1: string[] = [];
  for (const element of params.header.split(",")) {
    const eq = element.indexOf("=");
    if (eq < 0) return { ok: false, reason: "malformed_header" };
    const prefix = element.slice(0, eq).trim();
    const value = element.slice(eq + 1).trim();
    if (prefix === "t") {
      tCount += 1;
      t = value;
    } else if (prefix === "v1") {
      v1.push(value);
    }
    // every other scheme is discarded on purpose
  }
  if (tCount !== 1 || t === undefined || v1.length === 0) return { ok: false, reason: "malformed_header" };
  if (!/^\d{1,15}$/.test(t)) return { ok: false, reason: "malformed_timestamp" };
  const timestampSeconds = Number(t);

  const candidates: Buffer[] = [];
  for (const sig of v1) {
    if (/^[0-9a-fA-F]{64}$/.test(sig)) candidates.push(Buffer.from(sig, "hex"));
  }

  let matched = false;
  for (const secret of secrets) {
    const expected = createHmac("sha256", secret).update(t).update(".").update(params.body).digest();
    for (const candidate of candidates) {
      if (timingSafeEqual(expected, candidate)) matched = true;
    }
  }
  if (!matched) return { ok: false, reason: "signature_mismatch" };

  const ageSeconds = (params.nowMs ?? Date.now()) / 1000 - timestampSeconds;
  if (ageSeconds > toleranceSeconds) return { ok: false, reason: "timestamp_too_old" };
  if (-ageSeconds > toleranceSeconds) return { ok: false, reason: "timestamp_in_future" };
  return { ok: true, timestampMs: timestampSeconds * 1000 };
}
