import { createHmac } from "node:crypto";
import { describe, expect, test, vi } from "vitest";
import {
  createMemoryStore,
  handleWebhook,
  signedHeaders,
  type HandleWebhookOptions,
  type Store,
  type WebhookEvent,
} from "../src/index.js";
import { NOW, SECRET, deferred, makeClock, storeFactories } from "./helpers.js";

const payload = { id: "evt_1", type: "order.paid", orderId: "ord_42", amount: 4200 };
const RAW = JSON.stringify(payload);

type Overrides = Partial<Omit<HandleWebhookOptions, "handler" | "store">>;

/** A correctly signed request for `body`, as a sender would produce it at time `at`. */
function signedRequest(body: string = RAW, at = NOW, secret = SECRET, eventId: string | undefined = undefined) {
  return {
    rawBody: body,
    headers: signedHeaders({ secret, body, now: at, eventType: "order.paid", ...(eventId ? { eventId } : {}) }),
  };
}

function setup(store: Store = createMemoryStore({ now: () => NOW }), handlerImpl?: () => void | Promise<void>) {
  const handler = vi.fn<(event: WebhookEvent) => void | Promise<void>>(handlerImpl ?? (() => undefined));
  const call = (request: { rawBody: HandleWebhookOptions["rawBody"]; headers: HandleWebhookOptions["headers"] }, overrides: Overrides = {}) =>
    handleWebhook({ ...request, secret: SECRET, handler, store, now: () => NOW, ...overrides });
  return { handler, store, call };
}

describe("signature failures never run the handler and never touch the store", () => {
  function spiedStore() {
    const inner = createMemoryStore({ now: () => NOW });
    return {
      begin: vi.fn(inner.begin),
      complete: vi.fn(inner.complete),
      fail: vi.fn(inner.fail),
    } satisfies Store;
  }

  const cases: Array<[string, () => ReturnType<typeof signedRequest>, Overrides, number, string, string]> = [
    ["tampered body", () => ({ ...signedRequest(), rawBody: RAW.replace("4200", "9999") }), {}, 401, "invalid_signature", "signature_mismatch"],
    ["wrong secret", () => signedRequest(RAW, NOW, "attacker-secret"), {}, 401, "invalid_signature", "signature_mismatch"],
    ["expired", () => signedRequest(RAW, NOW - 6 * 60_000), {}, 401, "invalid_signature", "timestamp_too_old"],
    ["future timestamp", () => signedRequest(RAW, NOW + 10 * 60_000), {}, 401, "invalid_signature", "timestamp_in_future"],
    ["no signature headers at all", () => ({ rawBody: RAW, headers: {} }), {}, 400, "missing_signature", "missing_header"],
    [
      "signature without timestamp",
      () => {
        const r = signedRequest();
        return { rawBody: r.rawBody, headers: { "X-Webhook-Signature": r.headers["X-Webhook-Signature"] } };
      },
      {},
      400,
      "missing_signature",
      "missing_header",
    ],
    [
      "malformed signature header",
      () => ({ rawBody: RAW, headers: { ...signedRequest().headers, "X-Webhook-Signature": "not-a-signature" } }),
      {},
      400,
      "malformed_signature",
      "malformed_header",
    ],
    [
      "malformed timestamp",
      () => ({ rawBody: RAW, headers: { ...signedRequest().headers, "X-Webhook-Timestamp": "yesterday-ish" } }),
      {},
      400,
      "malformed_signature",
      "malformed_timestamp",
    ],
  ];

  test.each(cases)("%s", async (_name, build, overrides, status, error, reason) => {
    const store = spiedStore();
    const { handler, call } = setup(store);
    const response = await call(build(), overrides);
    expect(response.status).toBe(status);
    expect(response.body).toEqual({ error });
    expect(response.reason).toBe(reason);
    expect(handler).not.toHaveBeenCalled();
    expect(store.begin).not.toHaveBeenCalled();
    expect(store.complete).not.toHaveBeenCalled();
    expect(store.fail).not.toHaveBeenCalled();
  });

  test("a forged signature and a stale one get the same answer, so the caller learns nothing about the window", async () => {
    const { call } = setup();
    const forged = await call(signedRequest(RAW, NOW, "attacker-secret"));
    const stale = await call(signedRequest(RAW, NOW - 6 * 60_000));
    expect(forged.status).toBe(stale.status);
    expect(forged.body).toEqual(stale.body);
  });

  test("re-serialised JSON (the usual cause of 'signature failing') is rejected; the raw bytes are accepted", async () => {
    const { handler, call } = setup();
    const request = signedRequest();
    const reserialised = JSON.stringify(JSON.parse(RAW), null, 2);
    expect((await call({ ...request, rawBody: reserialised })).status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
    expect((await call(request)).status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });
});

describe("a valid request", () => {
  test("runs the handler once with the id, parsed payload and raw body, and answers 200", async () => {
    const { handler, call } = setup();
    const request = signedRequest();
    const response = await call(request);
    expect(response).toEqual({ status: 200, body: { status: "ok" } });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ id: "evt_1", payload, rawBody: RAW });
  });

  test("accepts a Buffer / Uint8Array raw body (what Express's raw() and Node streams give you)", async () => {
    const { handler, call } = setup();
    const bytes = Buffer.from(RAW, "utf8");
    const response = await call({ rawBody: bytes, headers: signedRequest().headers });
    expect(response.status).toBe(200);
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ payload });
  });

  test("header lookup is case-insensitive and works with a Web Headers object and array values", async () => {
    const { call } = setup(createMemoryStore({ now: () => NOW }));
    const { headers } = signedRequest();
    const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
    expect((await call({ rawBody: RAW, headers: lower })).status).toBe(200);

    const { call: call2 } = setup(createMemoryStore({ now: () => NOW }));
    expect((await call2({ rawBody: RAW, headers: new Headers(headers) })).status).toBe(200);

    const { call: call3 } = setup(createMemoryStore({ now: () => NOW }));
    const arrays = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, [v]]));
    expect((await call3({ rawBody: RAW, headers: arrays })).status).toBe(200);
  });

  test("secret rotation: either the old or the new secret verifies while both are configured", async () => {
    for (const signer of ["old-secret", "new-secret"]) {
      const { call } = setup(createMemoryStore({ now: () => NOW }));
      const response = await call(signedRequest(RAW, NOW, signer), { secret: ["new-secret", "old-secret"] });
      expect(response.status).toBe(200);
    }
  });

  test("the dedupe key comes from X-Webhook-Id when present, otherwise from payload.id", async () => {
    const { handler, call } = setup();
    await call(signedRequest(RAW, NOW, SECRET, "header-id-9"));
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ id: "header-id-9" });
  });

  test("no usable event id: 400, handler not run (dedupe is impossible without one)", async () => {
    const { handler, call } = setup();
    const response = await call(signedRequest(JSON.stringify({ type: "order.paid" })));
    expect(response).toMatchObject({ status: 400, body: { error: "missing_event_id" }, reason: "missing_event_id" });
    expect(handler).not.toHaveBeenCalled();

    const tooLong = await call(signedRequest(JSON.stringify({ id: "x".repeat(300) })));
    expect(tooLong.status).toBe(400);
  });

  test("a custom eventId function can use any field", async () => {
    const { handler, call } = setup();
    const body = JSON.stringify({ order: { ref: "A-1" } });
    const response = await call(signedRequest(body), {
      eventId: ({ payload: p }) => (p as { order: { ref: string } }).order.ref,
    });
    expect(response.status).toBe(200);
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ id: "A-1" });
  });

  test("a body that is not JSON still works when the id comes from a header", async () => {
    const { handler, call } = setup();
    const body = "plain text, not json";
    const response = await call(signedRequest(body, NOW, SECRET, "evt_text"));
    expect(response.status).toBe(200);
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ id: "evt_text", payload: undefined });
  });
});

describe.each(storeFactories)("duplicates, replays and failures (%s store)", (_name, make) => {
  test("duplicate event: the second delivery of a handled id answers 200 and does NOT run the handler", async () => {
    const { handler, call } = setup(make(() => NOW));
    const request = signedRequest();
    expect(await call(request)).toEqual({ status: 200, body: { status: "ok" } });
    expect(await call(request)).toEqual({ status: 200, body: { status: "duplicate" } });
    expect(await call(request)).toEqual({ status: 200, body: { status: "duplicate" } });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test("duplicate event delivered by the sender again with a fresh signature is still a duplicate", async () => {
    const { handler, call } = setup(make(() => NOW));
    await call(signedRequest());
    const again = await call(signedRequest(RAW, NOW + 60_000), { now: () => NOW + 60_000 });
    expect(again.body).toEqual({ status: "duplicate" });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test("replay: a captured request replayed inside the window is caught by dedupe; after the window by the timestamp", async () => {
    const clock = makeClock();
    const { handler, call } = setup(make(clock.now));
    const captured = signedRequest(RAW, clock.now());
    expect((await call(captured, { now: clock.now })).status).toBe(200);

    clock.advance(2 * 60_000);
    expect((await call(captured, { now: clock.now })).body).toEqual({ status: "duplicate" });

    clock.advance(10 * 60_000);
    const late = await call(captured, { now: clock.now });
    expect(late).toMatchObject({ status: 401, reason: "timestamp_too_old" });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test("concurrent duplicates: 6 simultaneous deliveries of one event run the handler exactly once", async () => {
    const gate = deferred();
    const { handler, call } = setup(make(() => NOW), () => gate.promise);
    const request = signedRequest();

    const inFlight = Array.from({ length: 6 }, () => call(request));
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));
    gate.resolve();
    const responses = await Promise.all(inFlight);

    expect(handler).toHaveBeenCalledTimes(1);
    expect(responses.filter((r) => r.status === 200 && r.body.status === "ok")).toHaveLength(1);
    expect(responses.filter((r) => r.status === 409 && r.body.status === "in_flight")).toHaveLength(5);

    // After it finished, the same delivery is just a duplicate.
    expect(await call(request)).toEqual({ status: 200, body: { status: "duplicate" } });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  test("an in-flight duplicate is answered 409 (retry later), not 200, so a first attempt that then fails is not lost", async () => {
    const gate = deferred();
    let calls = 0;
    const { handler, call } = setup(make(() => NOW), async () => {
      calls += 1;
      if (calls === 1) {
        await gate.promise;
        throw new Error("db went away");
      }
    });
    const request = signedRequest();
    const first = call(request);
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));

    const second = await call(request);
    expect(second.status).toBe(409);

    gate.resolve();
    expect((await first).status).toBe(500);
    // The sender retries the 409 and now gets the event processed.
    expect((await call(request)).status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(2);
  });

  test("handler failure answers 500 without leaking the error; a later retry runs the handler again and succeeds", async () => {
    let calls = 0;
    const { handler, call } = setup(make(() => NOW), () => {
      calls += 1;
      if (calls === 1) throw new Error("secret-db-password-in-message");
    });
    const request = signedRequest();

    const failed = await call(request);
    expect(failed.status).toBe(500);
    expect(failed.body).toEqual({ error: "handler_failed" });
    expect(JSON.stringify(failed.body)).not.toContain("secret-db-password");
    expect(failed.reason).toBe("handler_failed");
    expect((failed.error as Error).message).toContain("secret-db-password"); // available to YOUR logs

    const retried = await call(request);
    expect(retried).toEqual({ status: 200, body: { status: "ok" } });
    expect(handler).toHaveBeenCalledTimes(2);

    expect((await call(request)).body).toEqual({ status: "duplicate" });
    expect(handler).toHaveBeenCalledTimes(2);
  });

  test("an async handler rejection is treated the same as a throw", async () => {
    let calls = 0;
    const { call } = setup(make(() => NOW), async () => {
      calls += 1;
      if (calls === 1) throw new Error("async boom");
    });
    const request = signedRequest();
    expect((await call(request)).status).toBe(500);
    expect((await call(request)).status).toBe(200);
  });
});

describe("store trouble", () => {
  test("if the store cannot be reached the handler does not run and the sender is told to retry (500)", async () => {
    const store: Store = {
      begin: async () => {
        throw new Error("connection refused");
      },
      complete: async () => undefined,
      fail: async () => undefined,
    };
    const { handler, call } = setup(store);
    const response = await call(signedRequest());
    expect(response).toMatchObject({ status: 500, body: { error: "store_error" }, reason: "store_error" });
    expect(handler).not.toHaveBeenCalled();
  });

  test("if fail() throws while releasing a failed event, the caller still gets the handler's 500", async () => {
    const inner = createMemoryStore({ now: () => NOW });
    const store: Store = {
      begin: inner.begin,
      complete: inner.complete,
      fail: async () => {
        throw new Error("also down");
      },
    };
    const { call } = setup(store, () => {
      throw new Error("boom");
    });
    expect(await call(signedRequest())).toMatchObject({ status: 500, body: { error: "handler_failed" } });
  });

  test("if complete() throws after the handler succeeded: 500 so the sender retries (handlers must tolerate a re-run)", async () => {
    const inner = createMemoryStore({ now: () => NOW });
    const store: Store = {
      begin: inner.begin,
      complete: async () => {
        throw new Error("write failed");
      },
      fail: inner.fail,
    };
    const { handler, call } = setup(store);
    expect(await call(signedRequest())).toMatchObject({ status: 500, body: { error: "store_error" } });
    expect(handler).toHaveBeenCalledTimes(1);
  });
});

describe("stripe scheme", () => {
  const stripePayload = JSON.stringify({ id: "evt_stripe_1", object: "event", type: "payment_intent.succeeded" });
  const t = Math.floor(NOW / 1000);
  const stripeHeaders = (body = stripePayload, secret = "whsec_unit_test", at = t) => ({
    "Stripe-Signature": `t=${at},v1=${createHmac("sha256", secret).update(`${at}.${body}`).digest("hex")}`,
  });

  test("verifies Stripe-Signature, dedupes on payload.id, and ignores the generic headers", async () => {
    const { handler, call } = setup();
    const opts: Overrides = { scheme: "stripe", secret: "whsec_unit_test" };
    const request = { rawBody: stripePayload, headers: stripeHeaders() };
    expect(await call(request, opts)).toEqual({ status: 200, body: { status: "ok" } });
    expect(await call(request, opts)).toEqual({ status: 200, body: { status: "duplicate" } });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]?.[0]).toMatchObject({ id: "evt_stripe_1" });
  });

  test("a Stripe-scheme endpoint rejects requests that only carry the generic headers", async () => {
    const { handler, call } = setup();
    const response = await call(signedRequest(stripePayload), { scheme: "stripe", secret: "whsec_unit_test" });
    expect(response).toMatchObject({ status: 400, reason: "missing_header" });
    expect(handler).not.toHaveBeenCalled();
  });

  test("tampered, wrong-secret and expired Stripe requests are rejected without running the handler", async () => {
    const { handler, call } = setup();
    const opts: Overrides = { scheme: "stripe", secret: "whsec_unit_test" };
    expect((await call({ rawBody: stripePayload.replace("succeeded", "failed"), headers: stripeHeaders() }, opts)).status).toBe(401);
    expect((await call({ rawBody: stripePayload, headers: stripeHeaders(stripePayload, "whsec_other") }, opts)).status).toBe(401);
    const old = t - 600;
    expect((await call({ rawBody: stripePayload, headers: stripeHeaders(stripePayload, "whsec_unit_test", old) }, opts)).reason).toBe(
      "timestamp_too_old",
    );
    expect(handler).not.toHaveBeenCalled();
  });
});
