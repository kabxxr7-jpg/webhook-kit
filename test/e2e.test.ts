import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, test } from "vitest";
import { createMemoryLog, createMemoryStore, deliverWithRetry, handleWebhook, type WebhookEvent } from "../src/index.js";
import { SECRET } from "./helpers.js";

/**
 * Real HTTP on loopback: the sender uses the real global fetch, the receiver reads the raw request
 * bytes from the stream exactly as an Express raw() / Next `req.text()` route would.
 */
let server: http.Server | undefined;

afterEach(async () => {
  if (!server) return;
  server.closeAllConnections();
  await new Promise((resolve) => server?.close(resolve));
  server = undefined;
});

async function startReceiver(options: { handler: (e: WebhookEvent) => void | Promise<void>; reserialise?: boolean; secret?: string }) {
  const store = createMemoryStore();
  const statuses: number[] = [];
  server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    let rawBody: Buffer | string = Buffer.concat(chunks);
    // The classic bug: a body parser runs first and the code verifies JSON.stringify(parsed).
    if (options.reserialise) rawBody = JSON.stringify(JSON.parse(rawBody.toString("utf8")), null, 2);
    const response = await handleWebhook({
      rawBody,
      headers: req.headers,
      secret: options.secret ?? SECRET,
      handler: options.handler,
      store,
    });
    statuses.push(response.status);
    res.statusCode = response.status;
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(response.body));
  });
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/hooks`, statuses };
}

const noWait = async () => undefined;

describe("orders created twice (the recipe, end to end)", () => {
  test("a transient handler failure is retried and the order is created once; a re-delivery of the same event creates nothing", async () => {
    const orders = new Map<string, { amount: number }>();
    let attempts = 0;
    const { url, statuses } = await startReceiver({
      handler: ({ payload }) => {
        attempts += 1;
        if (attempts === 1) throw new Error("database timeout"); // first try fails before any write
        const p = payload as { orderId: string; amount: number };
        orders.set(p.orderId, { amount: p.amount });
      },
    });

    const log = createMemoryLog();
    const first = await deliverWithRetry(
      { secret: SECRET, log, sleep: noWait, timeoutMs: 2000 },
      url,
      { id: "evt_100", type: "order.paid", payload: { orderId: "ord_42", amount: 4200 } },
    );
    expect(first.success).toBe(true);
    expect(first.attempts.map((a) => a.statusCode)).toEqual([500, 200]);
    expect(orders.size).toBe(1);
    expect(attempts).toBe(2);

    // The provider sends the same event again (their retry raced our ack, or someone replays it).
    const again = await deliverWithRetry(
      { secret: SECRET, log, sleep: noWait, timeoutMs: 2000 },
      url,
      { id: "evt_100", type: "order.paid", payload: { orderId: "ord_42", amount: 4200 } },
    );
    expect(again.success).toBe(true);
    expect(again.attempts[0]?.responseSnippet).toBe('{"status":"duplicate"}');
    expect(orders.size).toBe(1);
    expect(attempts).toBe(2);
    expect(statuses).toEqual([500, 200, 200]);
    expect(log.entries.map((e) => e.statusCode)).toEqual([500, 200, 200]);
  });

  test("a different event id is a different event, even for the same order (dedupe is by event id, not by content)", async () => {
    const seen: string[] = [];
    const { url } = await startReceiver({ handler: ({ id }) => void seen.push(id) });
    const opts = { secret: SECRET, log: createMemoryLog(), sleep: noWait, timeoutMs: 2000 };
    await deliverWithRetry(opts, url, { id: "evt_1", type: "order.paid", payload: { orderId: "ord_1" } });
    await deliverWithRetry(opts, url, { id: "evt_2", type: "order.paid", payload: { orderId: "ord_1" } });
    expect(seen).toEqual(["evt_1", "evt_2"]);
  });
});

describe("signature failures over real HTTP", () => {
  test("a sender with the wrong secret is rejected on every attempt and the handler never runs", async () => {
    let ran = 0;
    const { url, statuses } = await startReceiver({ handler: () => void (ran += 1) });
    const log = createMemoryLog();
    const result = await deliverWithRetry(
      { secret: "not-the-receivers-secret", log, sleep: noWait, timeoutMs: 2000 },
      url,
      { id: "evt_1", type: "order.paid", payload: { orderId: "ord_1" } },
    );
    expect(result.success).toBe(false);
    expect(ran).toBe(0);
    expect(statuses).toEqual([401, 401, 401]);
    expect(log.entries.map((e) => [e.attempt, e.statusCode, e.nextRetryAt === null])).toEqual([
      [1, 401, false],
      [2, 401, false],
      [3, 401, true],
    ]);
  });

  test("verifying a re-serialised body instead of the raw bytes fails every time, even with the right secret", async () => {
    let ran = 0;
    const { url, statuses } = await startReceiver({ handler: () => void (ran += 1), reserialise: true });
    const result = await deliverWithRetry(
      { secret: SECRET, log: createMemoryLog(), sleep: noWait, timeoutMs: 2000 },
      url,
      { id: "evt_1", type: "order.paid", payload: { orderId: "ord_1", amount: 1 } },
    );
    expect(result.success).toBe(false);
    expect(ran).toBe(0);
    expect(statuses).toEqual([401, 401, 401]);
  });

  test("the same payload with the raw bytes is accepted (control for the test above)", async () => {
    let ran = 0;
    const { url } = await startReceiver({ handler: () => void (ran += 1) });
    const result = await deliverWithRetry(
      { secret: SECRET, log: createMemoryLog(), sleep: noWait, timeoutMs: 2000 },
      url,
      { id: "evt_1", type: "order.paid", payload: { orderId: "ord_1", amount: 1 } },
    );
    expect(result.success).toBe(true);
    expect(ran).toBe(1);
  });

  test("non-ASCII payloads survive the round trip byte for byte", async () => {
    const received: unknown[] = [];
    const { url } = await startReceiver({ handler: ({ payload }) => void received.push(payload) });
    const payload = { customer: "Zoë Müller 田中", note: "emoji 🚀 and   line separator" };
    const result = await deliverWithRetry(
      { secret: SECRET, log: createMemoryLog(), sleep: noWait, timeoutMs: 2000 },
      url,
      { id: "evt_utf8", type: "customer.created", payload },
    );
    expect(result.success).toBe(true);
    expect(received).toEqual([payload]);
  });
});
