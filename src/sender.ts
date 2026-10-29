import { randomUUID } from "node:crypto";
import { signedHeaders } from "./sign.js";

/** After attempt 1 fails wait 30 s, after attempt 2 wait 5 min, after attempt 3 give up (same as Opsflow). */
export const DEFAULT_RETRY_SCHEDULE_MS: readonly number[] = [30_000, 5 * 60_000];
export const DEFAULT_MAX_ATTEMPTS = 3;
export const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 4096;
const MAX_SNIPPET_CHARS = 2000;

export interface DeliveryLogEntry {
  eventId: string;
  eventType: string;
  url: string;
  attempt: number;
  /** ISO-8601 time the attempt started. */
  startedAt: string;
  durationMs: number;
  /** `null` when no HTTP response arrived (network error, timeout). */
  statusCode: number | null;
  success: boolean;
  /** First 2000 characters of the response body, read up to 4096 bytes. */
  responseSnippet: string | null;
  error: string | null;
  /** ISO-8601 time the next attempt is due; `null` after success or after the last attempt. */
  nextRetryAt: string | null;
}

export interface DeliveryLog {
  record(entry: DeliveryLogEntry): void | Promise<void>;
}

export interface MemoryLog extends DeliveryLog {
  readonly entries: DeliveryLogEntry[];
}

/** Keeps entries in an array. Replace with a table writer in a real project. */
export function createMemoryLog(): MemoryLog {
  const entries: DeliveryLogEntry[] = [];
  return {
    entries,
    record(entry) {
      entries.push(entry);
    },
  };
}

export interface SenderOptions {
  secret: string;
  log: DeliveryLog;
  /** Injected in tests. Default `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Epoch milliseconds. Default `Date.now`. */
  now?: () => number;
  /** Default: `setTimeout`. Tests inject a recorder or use fake timers. */
  sleep?: (ms: number) => Promise<void>;
  /** Delay after failed attempt n is `retryScheduleMs[n - 1]` (the last entry repeats). */
  retryScheduleMs?: readonly number[];
  maxAttempts?: number;
  /** Hard deadline for one attempt: connect, response and the capped body read. */
  timeoutMs?: number;
  /** Decide whether a failure is worth another attempt. Default: always (as in Opsflow). */
  shouldRetry?: (failure: { statusCode: number | null }) => boolean;
  userAgent?: string;
}

export interface OutgoingEvent {
  /** Stable across retries: it is what the receiver dedupes on. Generated if omitted. */
  id?: string;
  type: string;
  payload: unknown;
}

export interface AttemptResult extends DeliveryLogEntry {
  /** Set if `log.record` threw; the delivery itself is unaffected. */
  logError?: string;
}

export interface DeliveryResult {
  success: boolean;
  eventId: string;
  attempts: AttemptResult[];
}

/** Delay before the attempt that follows failed attempt `failedAttempt`, or `null` to give up. */
export function nextRetryDelayMs(
  failedAttempt: number,
  schedule: readonly number[] = DEFAULT_RETRY_SCHEDULE_MS,
  maxAttempts: number = DEFAULT_MAX_ATTEMPTS,
): number | null {
  if (failedAttempt >= maxAttempts) return null;
  const delay = schedule[failedAttempt - 1] ?? schedule[schedule.length - 1];
  return delay ?? null;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

async function readSnippet(response: Response): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  try {
    while (received < MAX_RESPONSE_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.byteLength;
    }
  } finally {
    // Stop reading instead of draining a body that never ends. Not awaited: a cancel that waits on
    // the other side of a teed stream must not hold up the delivery result.
    reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(Math.min(received, MAX_RESPONSE_BYTES));
  let offset = 0;
  for (const chunk of chunks) {
    const room = bytes.length - offset;
    if (room <= 0) break;
    bytes.set(chunk.subarray(0, room), offset);
    offset += Math.min(chunk.byteLength, room);
  }
  return new TextDecoder().decode(bytes).slice(0, MAX_SNIPPET_CHARS);
}

/**
 * One signed POST, one log entry. Signs with a fresh timestamp every call, so a retry is never
 * rejected by the receiver's replay window. Redirects are not followed (a 3xx is a failure).
 * Does NOT guard against private-network targets; see README.
 */
export async function sendOnce(
  options: SenderOptions,
  url: string,
  event: Required<OutgoingEvent>,
  attempt: number,
): Promise<{ result: AttemptResult; retryDelayMs: number | null }> {
  const now = options.now ?? Date.now;
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;

  const body = JSON.stringify(event.payload);
  const startedMs = now();
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": options.userAgent ?? "webhook-kit/0.1",
    ...signedHeaders({ secret: options.secret, body, now: startedMs, eventType: event.type, eventId: event.id }),
  };

  let statusCode: number | null = null;
  let responseSnippet: string | null = null;
  let success = false;
  let error: string | null = null;

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`Timed out after ${timeoutMs / 1000}s`));
    }, timeoutMs);
  });
  const exchange = (async () => {
    const response = await doFetch(url, { method: "POST", headers, body, redirect: "manual", signal: controller.signal });
    statusCode = response.status;
    responseSnippet = await readSnippet(response);
    success = response.status >= 200 && response.status < 300;
    if (!success) error = `Non-2xx response: ${response.status}`;
  })();
  exchange.catch(() => undefined); // if the deadline wins, don't leave an unhandled rejection behind

  try {
    await Promise.race([exchange, deadline]);
  } catch (caught) {
    success = false;
    error = caught instanceof Error ? caught.message : "Unknown delivery error";
  } finally {
    clearTimeout(timer);
  }

  const retryable = !success && (options.shouldRetry ? options.shouldRetry({ statusCode }) : true);
  const retryDelayMs = retryable ? nextRetryDelayMs(attempt, options.retryScheduleMs, maxAttempts) : null;
  const finishedMs = now();

  const result: AttemptResult = {
    eventId: event.id,
    eventType: event.type,
    url,
    attempt,
    startedAt: new Date(startedMs).toISOString(),
    durationMs: finishedMs - startedMs,
    statusCode,
    success,
    responseSnippet,
    error,
    nextRetryAt: retryDelayMs === null ? null : new Date(finishedMs + retryDelayMs).toISOString(),
  };
  try {
    await options.log.record(result);
  } catch (logFailure) {
    result.logError = logFailure instanceof Error ? logFailure.message : String(logFailure);
  }
  return { result, retryDelayMs };
}

/**
 * Attempt, wait, attempt... up to `maxAttempts`, logging every attempt. In-process: it holds the
 * caller until the last attempt finishes, so use it from a worker or a queue consumer, not from a
 * request handler. For serverless, call `sendOnce` per attempt and let a scheduler re-run entries
 * whose `nextRetryAt` has passed (what Opsflow's cron sweep does).
 */
export async function deliverWithRetry(options: SenderOptions, url: string, event: OutgoingEvent): Promise<DeliveryResult> {
  const sleep = options.sleep ?? defaultSleep;
  const full: Required<OutgoingEvent> = { id: event.id ?? randomUUID(), type: event.type, payload: event.payload };
  const attempts: AttemptResult[] = [];

  for (let attempt = 1; ; attempt += 1) {
    const { result, retryDelayMs } = await sendOnce(options, url, full, attempt);
    attempts.push(result);
    if (result.success) return { success: true, eventId: full.id, attempts };
    if (retryDelayMs === null) return { success: false, eventId: full.id, attempts };
    await sleep(retryDelayMs);
  }
}
