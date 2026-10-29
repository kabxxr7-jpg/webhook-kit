import { createHmac, timingSafeEqual } from "node:crypto";

/** A request body exactly as received. Never a re-serialised object: the signature covers the bytes. */
export type Body = string | Uint8Array;

export const DEFAULT_TOLERANCE_MS = 5 * 60_000;

export type VerifyFailure =
  | "missing_header"
  | "malformed_header"
  | "malformed_timestamp"
  | "signature_mismatch"
  | "timestamp_too_old"
  | "timestamp_in_future";

export type VerifyResult = { ok: true; timestampMs: number } | { ok: false; reason: VerifyFailure };

/**
 * Same scheme as Opsflow's lib/webhooks.ts: HMAC-SHA256, hex, over `${timestamp}.${body}`.
 * The timestamp is part of the signed string so the receiver can enforce a replay window.
 * `Uint8Array` bodies are signed byte for byte (identical to the string form for UTF-8 text).
 */
export function signPayload(secret: string, timestamp: string, body: Body): string {
  assertSecret(secret);
  return createHmac("sha256", secret).update(timestamp).update(".").update(body).digest("hex");
}

/** The value of the `X-Webhook-Signature` header: `sha256=<hex>`. */
export function signatureHeader(secret: string, timestamp: string, body: Body): string {
  return `sha256=${signPayload(secret, timestamp, body)}`;
}

/** Headers a sender attaches. `now` is epoch milliseconds (injectable for tests). */
export function signedHeaders(params: {
  secret: string;
  body: Body;
  now?: number;
  eventType?: string;
  eventId?: string;
}): Record<string, string> {
  const timestamp = new Date(params.now ?? Date.now()).toISOString();
  const headers: Record<string, string> = {
    "X-Webhook-Signature": signatureHeader(params.secret, timestamp, params.body),
    "X-Webhook-Timestamp": timestamp,
  };
  if (params.eventType) headers["X-Webhook-Event"] = params.eventType;
  if (params.eventId) headers["X-Webhook-Id"] = params.eventId;
  return headers;
}

const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;

/**
 * Strict ISO-8601 with a time zone (what `Date#toISOString` emits). Stricter than Date.parse on
 * purpose: Date.parse("1") is a valid date in V8, which is not a timestamp a signer would send.
 */
export function parseTimestamp(timestamp: string): number | null {
  if (!ISO_8601.test(timestamp)) return null;
  const ms = Date.parse(timestamp);
  return Number.isNaN(ms) ? null : ms;
}

const SHA256_VALUE = /^sha256=([0-9a-fA-F]{64})$/;

/**
 * `sha256=<64 hex>`; several comma-separated values are allowed (secret rotation: the sender
 * signs once per active secret). Anything else in the header makes the whole header malformed.
 */
function parseSignatureHeader(header: string): Buffer[] | null {
  const parts = header.split(",").map((p) => p.trim());
  const out: Buffer[] = [];
  for (const part of parts) {
    const m = SHA256_VALUE.exec(part);
    if (!m || !m[1]) return null;
    out.push(Buffer.from(m[1], "hex"));
  }
  return out.length > 0 ? out : null;
}

export function assertSecret(secret: string): void {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new TypeError("webhook secret must be a non-empty string");
  }
}

export function assertTolerance(ms: number, unit = "ms"): void {
  if (!Number.isFinite(ms) || ms <= 0) {
    throw new RangeError(`tolerance must be a positive number of ${unit}; 0 would disable the replay window`);
  }
}

export interface VerifyParams {
  /** One secret, or several during rotation (a signature made with any of them is accepted). */
  secret: string | readonly string[];
  /** Value of `X-Webhook-Timestamp`. */
  timestamp: string | null | undefined;
  /** The raw request body, unparsed. */
  body: Body;
  /** Value of `X-Webhook-Signature`. */
  signatureHeader: string | null | undefined;
  /** Accepted distance between the timestamp and `nowMs`, in either direction. Default 5 minutes. */
  toleranceMs?: number;
  /** Epoch milliseconds; injectable for tests. */
  nowMs?: number;
}

/**
 * Verifies a request and says why it failed. Order matters: the signature is checked before the
 * timestamp window, so an unsigned or forged request never learns whether its timestamp was
 * acceptable. The window is symmetric: a timestamp more than `toleranceMs` ahead of the receiver's
 * clock is rejected the same as one that old; small skew inside the window is accepted.
 */
export function verifyWebhook(params: VerifyParams): VerifyResult {
  const secrets = typeof params.secret === "string" ? [params.secret] : [...params.secret];
  if (secrets.length === 0) throw new TypeError("at least one webhook secret is required");
  for (const s of secrets) assertSecret(s);
  const toleranceMs = params.toleranceMs ?? DEFAULT_TOLERANCE_MS;
  assertTolerance(toleranceMs);

  if (!params.signatureHeader || !params.timestamp) return { ok: false, reason: "missing_header" };
  const candidates = parseSignatureHeader(params.signatureHeader);
  if (!candidates) return { ok: false, reason: "malformed_header" };
  const timestampMs = parseTimestamp(params.timestamp);
  if (timestampMs === null) return { ok: false, reason: "malformed_timestamp" };

  // Compare against every secret x candidate without early exit.
  let matched = false;
  for (const secret of secrets) {
    const expected = createHmac("sha256", secret).update(params.timestamp).update(".").update(params.body).digest();
    for (const candidate of candidates) {
      if (timingSafeEqual(expected, candidate)) matched = true;
    }
  }
  if (!matched) return { ok: false, reason: "signature_mismatch" };

  const age = (params.nowMs ?? Date.now()) - timestampMs;
  if (age > toleranceMs) return { ok: false, reason: "timestamp_too_old" };
  if (-age > toleranceMs) return { ok: false, reason: "timestamp_in_future" };
  return { ok: true, timestampMs };
}

/**
 * Drop-in for Opsflow's `verifySignature` (same parameter names, plus `toleranceMs`; `maxAgeMs` is
 * accepted as an alias). Returns only a boolean; use `verifyWebhook` when you need the reason.
 */
export function verifySignature(params: {
  secret: string | readonly string[];
  timestamp: string | null | undefined;
  body: Body;
  signatureHeader: string | null | undefined;
  toleranceMs?: number;
  maxAgeMs?: number;
  nowMs?: number;
}): boolean {
  const { maxAgeMs, toleranceMs, ...rest } = params;
  const tolerance = toleranceMs ?? maxAgeMs;
  return verifyWebhook({ ...rest, ...(tolerance === undefined ? {} : { toleranceMs: tolerance }) }).ok;
}
