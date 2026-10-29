import { afterEach, describe, expect, test, vi } from "vitest";
import {
  DEFAULT_MAX_ATTEMPTS,
  DEFAULT_RETRY_SCHEDULE_MS,
  createMemoryLog,
  deliverWithRetry,
  nextRetryDelayMs,
  sendOnce,
  verifyWebhook,
  type DeliveryLog,
  type SenderOptions,
} from "../src/index.js";
import { NOW, SECRET, makeClock } from "./helpers.js";

const URL_ = "https://receiver.example/hooks/orders";
const event = { id: "evt_1", type: "order.paid", payload: { orderId: "ord_42", amount: 4200 } };

type Step = Response | Error | (() => Promise<Response>);

interface Captured {
  url: string;
  init: RequestInit & { headers: Record<string, string>; body: string };
}

/** A fetch that plays back `steps` in order and records every request. */
function scriptedFetch(steps: Step[]) {
  const calls: Captured[] = [];
  const impl = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init as Captured["init"] });
    const step = steps[Math.min(calls.length - 1, steps.length - 1)];
    if (step instanceof Error) throw step;
    if (typeof step === "function") return step();
    if (!step) throw new Error("scriptedFetch: no step");
    return step.clone();
  }) as typeof fetch;
  return { fetch: impl, calls };
}

const ok = () => new Response("ok", { status: 200 });
const status = (code: number, body = "") => new Response(body, { status: code });

/** Options with a hand-driven clock; `sleep` records the delay and moves the clock. */
function manual(steps: Step[], extra: Partial<SenderOptions> = {}) {
  const clock = makeClock();
  const log = createMemoryLog();
  const sleeps: number[] = [];
  const { fetch, calls } = scriptedFetch(steps);
  const options: SenderOptions = {
    secret: SECRET,
    log,
    fetch,
    now: clock.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock.advance(ms);
    },
    ...extra,
  };
  return { options, clock, log, sleeps, calls };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("nextRetryDelayMs", () => {
  test("defaults mirror Opsflow: 30 s after attempt 1, 5 min after attempt 2, give up after attempt 3", () => {
    expect(DEFAULT_RETRY_SCHEDULE_MS).toEqual([30_000, 300_000]);
    expect(DEFAULT_MAX_ATTEMPTS).toBe(3);
    expect(nextRetryDelayMs(1)).toBe(30_000);
    expect(nextRetryDelayMs(2)).toBe(300_000);
    expect(nextRetryDelayMs(3)).toBeNull();
    expect(nextRetryDelayMs(4)).toBeNull();
  });

  test("custom schedule and attempt limit; the last delay repeats when the schedule is short", () => {
    expect(nextRetryDelayMs(1, [1000], 4)).toBe(1000);
    expect(nextRetryDelayMs(3, [1000], 4)).toBe(1000);
    expect(nextRetryDelayMs(4, [1000], 4)).toBeNull();
    expect(nextRetryDelayMs(1, [], 3)).toBeNull();
  });
});

describe("a delivery", () => {
  test("sends one signed JSON POST that a receiver can verify, and logs a success", async () => {
    const { options, calls, log, sleeps } = manual([ok()]);
    const result = await deliverWithRetry(options, URL_, event);

    expect(result.success).toBe(true);
    expect(result.attempts).toHaveLength(1);
    expect(sleeps).toEqual([]);
    expect(calls).toHaveLength(1);

    const { url, init } = calls[0]!;
    expect(url).toBe(URL_);
    expect(init.method).toBe("POST");
    expect(init.redirect).toBe("manual");
    expect(init.headers["Content-Type"]).toBe("application/json");
    expect(init.headers["X-Webhook-Event"]).toBe("order.paid");
    expect(init.headers["X-Webhook-Id"]).toBe("evt_1");
    expect(init.body).toBe(JSON.stringify(event.payload));
    expect(
      verifyWebhook({
        secret: SECRET,
        timestamp: init.headers["X-Webhook-Timestamp"],
        signatureHeader: init.headers["X-Webhook-Signature"],
        body: init.body,
        nowMs: NOW,
      }),
    ).toEqual({ ok: true, timestampMs: NOW });

    expect(log.entries).toEqual([
      {
        eventId: "evt_1",
        eventType: "order.paid",
        url: URL_,
        attempt: 1,
        startedAt: new Date(NOW).toISOString(),
        durationMs: 0,
        statusCode: 200,
        success: true,
        responseSnippet: "ok",
        error: null,
        nextRetryAt: null,
      },
    ]);
  });

  test("backoff schedule: fails, waits 30 s, fails, waits 5 min, fails, gives up after attempt 3", async () => {
    const { options, calls, log, sleeps } = manual([status(500, "oops")]);
    const result = await deliverWithRetry(options, URL_, event);

    expect(result.success).toBe(false);
    expect(calls).toHaveLength(3);
    expect(sleeps).toEqual([30_000, 300_000]);

    const t0 = NOW;
    expect(log.entries.map((e) => [e.attempt, e.success, e.statusCode, e.error])).toEqual([
      [1, false, 500, "Non-2xx response: 500"],
      [2, false, 500, "Non-2xx response: 500"],
      [3, false, 500, "Non-2xx response: 500"],
    ]);
    expect(log.entries.map((e) => e.startedAt)).toEqual([
      new Date(t0).toISOString(),
      new Date(t0 + 30_000).toISOString(),
      new Date(t0 + 330_000).toISOString(),
    ]);
    expect(log.entries.map((e) => e.nextRetryAt)).toEqual([
      new Date(t0 + 30_000).toISOString(),
      new Date(t0 + 330_000).toISOString(),
      null,
    ]);
    expect(log.entries[0]?.responseSnippet).toBe("oops");
  });

  test("max attempts: never a 4th try with the defaults, however many failures", async () => {
    const { options, calls } = manual([status(503)]);
    await deliverWithRetry(options, URL_, event);
    expect(calls).toHaveLength(3);
  });

  test("a failure followed by a success stops retrying and logs both attempts", async () => {
    const { options, calls, log, sleeps } = manual([status(502), ok()]);
    const result = await deliverWithRetry(options, URL_, event);
    expect(result.success).toBe(true);
    expect(calls).toHaveLength(2);
    expect(sleeps).toEqual([30_000]);
    expect(log.entries.map((e) => [e.attempt, e.success, e.statusCode])).toEqual([
      [1, false, 502],
      [2, true, 200],
    ]);
    expect(log.entries[1]?.nextRetryAt).toBeNull();
  });

  test("configurable schedule and attempt limit", async () => {
    const { options, calls, sleeps } = manual([status(500)], { retryScheduleMs: [1000, 2000], maxAttempts: 4 });
    await deliverWithRetry(options, URL_, event);
    expect(calls).toHaveLength(4);
    expect(sleeps).toEqual([1000, 2000, 2000]);

    const single = manual([status(500)], { maxAttempts: 1 });
    const result = await deliverWithRetry(single.options, URL_, event);
    expect(result.success).toBe(false);
    expect(single.calls).toHaveLength(1);
    expect(single.sleeps).toEqual([]);
    expect(single.log.entries[0]?.nextRetryAt).toBeNull();
  });

  test("the event id is stable across retries; every attempt is signed fresh with its own timestamp", async () => {
    const { options, calls, clock } = manual([status(500), status(500), ok()]);
    await deliverWithRetry(options, URL_, event);

    expect(calls.map((c) => c.init.headers["X-Webhook-Id"])).toEqual(["evt_1", "evt_1", "evt_1"]);
    const stamps = calls.map((c) => c.init.headers["X-Webhook-Timestamp"]!);
    expect(new Set(stamps).size).toBe(3);

    const attemptTimes = [NOW, NOW + 30_000, NOW + 330_000];
    calls.forEach((c, i) => {
      // valid at its own send time, and the third is not valid against the first attempt's clock window
      expect(
        verifyWebhook({
          secret: SECRET,
          timestamp: c.init.headers["X-Webhook-Timestamp"],
          signatureHeader: c.init.headers["X-Webhook-Signature"],
          body: c.init.body,
          nowMs: attemptTimes[i]!,
        }).ok,
      ).toBe(true);
    });
    const third = calls[2]!;
    expect(
      verifyWebhook({
        secret: SECRET,
        timestamp: third.init.headers["X-Webhook-Timestamp"],
        signatureHeader: third.init.headers["X-Webhook-Signature"],
        body: third.init.body,
        nowMs: NOW,
        toleranceMs: 60_000,
      }),
    ).toEqual({ ok: false, reason: "timestamp_in_future" });
    expect(clock.now()).toBe(NOW + 330_000);
  });

  test("an id is generated when none is given, and stays the same across attempts", async () => {
    const { options, calls } = manual([status(500), ok()]);
    const result = await deliverWithRetry(options, URL_, { type: "order.paid", payload: { a: 1 } });
    expect(result.eventId).toMatch(/^[0-9a-f-]{36}$/);
    expect(calls.map((c) => c.init.headers["X-Webhook-Id"])).toEqual([result.eventId, result.eventId]);
    expect(result.attempts.every((a) => a.eventId === result.eventId)).toBe(true);
  });
});

describe("failure modes are logged, not thrown", () => {
  test("a network error is a logged failure with no status code, and is retried", async () => {
    const { options, log, calls } = manual([new TypeError("fetch failed"), ok()]);
    const result = await deliverWithRetry(options, URL_, event);
    expect(result.success).toBe(true);
    expect(calls).toHaveLength(2);
    expect(log.entries[0]).toMatchObject({ attempt: 1, success: false, statusCode: null, error: "fetch failed", responseSnippet: null });
  });

  test("a redirect is a failure and is not followed (fetch is told redirect: manual)", async () => {
    const { options, log, calls } = manual([new Response(null, { status: 302, headers: { location: "http://169.254.169.254/" } })], {
      maxAttempts: 1,
    });
    const result = await deliverWithRetry(options, URL_, event);
    expect(result.success).toBe(false);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init.redirect).toBe("manual");
    expect(log.entries[0]).toMatchObject({ statusCode: 302, success: false, error: "Non-2xx response: 302" });
  });

  test("shouldRetry can stop retries for failures that cannot get better (for example a 400)", async () => {
    const { options, calls, log, sleeps } = manual([status(400, "bad request")], {
      shouldRetry: ({ statusCode }) => statusCode === null || statusCode >= 500 || statusCode === 429,
    });
    const result = await deliverWithRetry(options, URL_, event);
    expect(result.success).toBe(false);
    expect(calls).toHaveLength(1);
    expect(sleeps).toEqual([]);
    expect(log.entries[0]?.nextRetryAt).toBeNull();
  });

  test("a response body is logged only as a short snippet (2000 characters)", async () => {
    const { options, log } = manual([status(500, "a".repeat(10_000))], { maxAttempts: 1 });
    await deliverWithRetry(options, URL_, event);
    expect(log.entries[0]?.responseSnippet).toHaveLength(2000);
  });

  test("a response that never ends is read only up to the cap, then dropped; a 2xx is still a success", async () => {
    let cancelled = false;
    let pulled = 0;
    const endless = () =>
      Promise.resolve(
        new Response(
          new ReadableStream<Uint8Array>({
            pull(controller) {
              pulled += 1;
              controller.enqueue(new TextEncoder().encode("x".repeat(1024)));
            },
            cancel() {
              cancelled = true;
            },
          }),
          { status: 200 },
        ),
      );
    const { options, log } = manual([endless]);
    const result = await deliverWithRetry(options, URL_, event);
    expect(result.success).toBe(true);
    expect(cancelled).toBe(true);
    expect(pulled).toBeLessThan(20);
    expect(log.entries[0]?.responseSnippet?.length).toBeLessThanOrEqual(2000);
  });

  test("a log that throws does not change the delivery outcome; the problem is reported on the attempt", async () => {
    const brokenLog: DeliveryLog = {
      record() {
        throw new Error("disk full");
      },
    };
    const { options } = manual([ok()], { log: brokenLog });
    const result = await deliverWithRetry(options, URL_, event);
    expect(result.success).toBe(true);
    expect(result.attempts[0]?.logError).toBe("disk full");
  });

  test("sendOnce does a single attempt and reports the delay the caller should schedule (queue or cron style)", async () => {
    const { options, log } = manual([status(500)]);
    const { result, retryDelayMs } = await sendOnce(options, URL_, event, 1);
    expect(retryDelayMs).toBe(30_000);
    expect(result.nextRetryAt).toBe(new Date(NOW + 30_000).toISOString());
    expect(log.entries).toHaveLength(1);
    const last = await sendOnce(options, URL_, event, 3);
    expect(last.retryDelayMs).toBeNull();
  });
});

describe("with fake timers (the default clock and sleep)", () => {
  test("the retry fires at 30 s and again at 5 min after that, not before", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    const log = createMemoryLog();
    const { fetch, calls } = scriptedFetch([status(500), status(500), ok()]);
    const done = deliverWithRetry({ secret: SECRET, log, fetch }, URL_, event);

    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(29_999);
    expect(calls).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(2);

    await vi.advanceTimersByTimeAsync(300_000 - 1);
    expect(calls).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(calls).toHaveLength(3);

    const result = await done;
    expect(result.success).toBe(true);
    expect(log.entries.map((e) => e.startedAt)).toEqual([
      new Date(NOW).toISOString(),
      new Date(NOW + 30_000).toISOString(),
      new Date(NOW + 330_000).toISOString(),
    ]);
  });

  test("a hung endpoint is cut off at the deadline: logged as a timeout and the request is aborted", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    const log = createMemoryLog();
    let signal: AbortSignal | undefined;
    const hanging = (async (_url: string | URL | Request, init?: RequestInit) => {
      signal = init?.signal ?? undefined;
      return new Promise<Response>(() => undefined);
    }) as typeof fetch;

    const pending = sendOnce({ secret: SECRET, log, fetch: hanging, timeoutMs: 2000 }, URL_, event, 1);
    await vi.advanceTimersByTimeAsync(1999);
    expect(log.entries).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);

    const { result, retryDelayMs } = await pending;
    expect(result).toMatchObject({ success: false, statusCode: null, error: "Timed out after 2s", durationMs: 2000 });
    expect(signal?.aborted).toBe(true);
    expect(retryDelayMs).toBe(30_000);
    expect(log.entries).toHaveLength(1);
  });

  test("a body that drips forever after a 200 is also cut off at the deadline", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    const log = createMemoryLog();
    const dripping = (async () =>
      new Response(new ReadableStream<Uint8Array>({ pull: () => new Promise<void>(() => undefined) }), { status: 200 })) as typeof fetch;

    const pending = sendOnce({ secret: SECRET, log, fetch: dripping, timeoutMs: 1000 }, URL_, event, 1);
    await vi.advanceTimersByTimeAsync(1000);
    const { result } = await pending;
    expect(result).toMatchObject({ success: false, error: "Timed out after 1s" });
  });
});
