import { getHeader, type HeadersLike } from "./headers.js";
import type { Store } from "./idempotency.js";
import { DEFAULT_LOCK_TIMEOUT_MS } from "./idempotency.js";
import { DEFAULT_TOLERANCE_MS, verifyWebhook, type Body, type VerifyFailure } from "./sign.js";
import { verifyStripeSignature } from "./stripe.js";

export interface WebhookEvent {
  /** The deduplication key (see `eventId`). */
  id: string;
  /** Parsed JSON body, or `undefined` if the body is not JSON. */
  payload: unknown;
  rawBody: Body;
  headers: HeadersLike;
}

export interface EventIdContext {
  headers: HeadersLike;
  payload: unknown;
  rawBody: Body;
}

export interface HandleWebhookOptions {
  /** The request body exactly as received. Not `JSON.stringify(req.body)`. */
  rawBody: Body;
  headers: HeadersLike;
  /** One secret, or two during rotation. */
  secret: string | readonly string[];
  /** Do the work. Throw to make the sender retry. Keep it short; enqueue slow work. */
  handler: (event: WebhookEvent) => void | Promise<void>;
  store: Store;
  /**
   * "generic": `X-Webhook-Signature` + `X-Webhook-Timestamp` (the scheme in sign.ts, same as Opsflow).
   * "stripe": `Stripe-Signature` (see stripe.ts). Default "generic".
   */
  scheme?: "generic" | "stripe";
  /** Replay window in either direction. Default 5 minutes. */
  toleranceMs?: number;
  /** How long an in-flight claim blocks other deliveries of the same id. Default 5 minutes. */
  lockTimeoutMs?: number;
  /**
   * Where the dedupe key comes from. Default: generic = `X-Webhook-Id` header, then `payload.id`;
   * stripe = `payload.id`. Return `undefined` to reject the request with 400.
   */
  eventId?: (context: EventIdContext) => string | undefined;
  /** Epoch milliseconds; injectable for tests. */
  now?: () => number;
}

export interface WebhookResponse {
  status: number;
  /** Safe to send to the caller: contains no internal detail. */
  body: { status?: "ok" | "duplicate" | "in_flight"; error?: string };
  /** Why a request was rejected or failed. For your logs, not for the caller. */
  reason?: VerifyFailure | "missing_event_id" | "handler_failed" | "store_error";
  /** The underlying error for `handler_failed` / `store_error`. */
  error?: unknown;
}

const MAX_ID_LENGTH = 255;

function defaultEventId(scheme: "generic" | "stripe", ctx: EventIdContext): string | undefined {
  if (scheme === "generic") {
    const fromHeader = getHeader(ctx.headers, "x-webhook-id");
    if (fromHeader) return fromHeader;
  }
  const payload = ctx.payload;
  if (payload && typeof payload === "object" && "id" in payload) {
    const id = (payload as { id: unknown }).id;
    if (typeof id === "string" || typeof id === "number") return String(id);
  }
  return undefined;
}

function parseJson(rawBody: Body): unknown {
  try {
    return JSON.parse(typeof rawBody === "string" ? rawBody : new TextDecoder().decode(rawBody));
  } catch {
    return undefined;
  }
}

function rejectionFor(reason: VerifyFailure): WebhookResponse {
  switch (reason) {
    case "missing_header":
      return { status: 400, body: { error: "missing_signature" }, reason };
    case "malformed_header":
    case "malformed_timestamp":
      return { status: 400, body: { error: "malformed_signature" }, reason };
    default:
      // signature_mismatch, timestamp_too_old, timestamp_in_future: one answer, so a caller
      // cannot tell a forged signature from a stale one.
      return { status: 401, body: { error: "invalid_signature" }, reason };
  }
}

/**
 * Framework-agnostic receiver: verify, dedupe, handle, answer.
 *
 *   bad/missing signature        400 / 401, handler NOT run, store untouched
 *   first delivery of an id      handler runs; 200 {status:"ok"}
 *   already-handled id           200 {status:"duplicate"}, handler NOT run
 *   same id still in flight      409 {status:"in_flight"}, handler NOT run (the sender should retry,
 *                                 because the first attempt may still fail)
 *   handler throws               500 {error:"handler_failed"}; the id is released so the retry re-runs it
 *   store unavailable            500 {error:"store_error"}; the handler did not run (or, if the store
 *                                 failed after it, may run again: handlers must tolerate that)
 */
export async function handleWebhook(options: HandleWebhookOptions): Promise<WebhookResponse> {
  const { rawBody, headers, secret, handler, store } = options;
  const scheme = options.scheme ?? "generic";
  const toleranceMs = options.toleranceMs ?? DEFAULT_TOLERANCE_MS;
  const nowMs = (options.now ?? Date.now)();

  const verdict =
    scheme === "stripe"
      ? verifyStripeSignature({
          secret,
          header: getHeader(headers, "stripe-signature"),
          body: rawBody,
          toleranceSeconds: toleranceMs / 1000,
          nowMs,
        })
      : verifyWebhook({
          secret,
          timestamp: getHeader(headers, "x-webhook-timestamp"),
          signatureHeader: getHeader(headers, "x-webhook-signature"),
          body: rawBody,
          toleranceMs,
          nowMs,
        });
  if (!verdict.ok) return rejectionFor(verdict.reason);

  const payload = parseJson(rawBody);
  const context: EventIdContext = { headers, payload, rawBody };
  const id = (options.eventId ?? ((ctx) => defaultEventId(scheme, ctx)))(context);
  if (!id || id.length > MAX_ID_LENGTH) {
    return { status: 400, body: { error: "missing_event_id" }, reason: "missing_event_id" };
  }

  let claim;
  try {
    claim = await store.begin(id, { lockTimeoutMs: options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS });
  } catch (error) {
    return { status: 500, body: { error: "store_error" }, reason: "store_error", error };
  }
  if (claim === "done") return { status: 200, body: { status: "duplicate" } };
  if (claim === "in_flight") return { status: 409, body: { status: "in_flight" } };

  try {
    await handler({ id, payload, rawBody, headers });
  } catch (error) {
    // Release the id so the sender's retry can run the handler again. A failure to release is
    // swallowed: the lock timeout frees it eventually, and the caller still gets its 500.
    await store.fail(id, error instanceof Error ? error.message : String(error)).catch(() => undefined);
    return { status: 500, body: { error: "handler_failed" }, reason: "handler_failed", error };
  }

  try {
    await store.complete(id);
  } catch (error) {
    return { status: 500, body: { error: "store_error" }, reason: "store_error", error };
  }
  return { status: 200, body: { status: "ok" } };
}
