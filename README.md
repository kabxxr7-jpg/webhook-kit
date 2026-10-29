# webhook-kit

> **Status:** a proof project (154 tests, run locally against local test servers and a SQLite store). Not used in production or by any client. See Limits below for what was not verified.

A tested starting point for the usual webhook jobs: "my webhook is unreliable", "orders get created twice", "signature verification keeps failing".

It gives you five small pieces that work together:

| Piece | File | What it does |
|---|---|---|
| Sign / verify | `src/sign.ts` | HMAC-SHA256 over `${timestamp}.${rawBody}`, constant-time compare, replay window in both directions, a reason for every rejection |
| Stripe verify | `src/stripe.ts` | The documented manual `Stripe-Signature` check (`t=`, one or more `v1=`, tolerance) |
| Idempotency | `src/idempotency.ts` | Event-id dedupe with `in_flight` / `done` / `failed` states, an in-memory store and a SQL store (Postgres dialect) |
| Receiver | `src/receiver.ts` | `handleWebhook(...)`: verify, dedupe, run your handler, answer with the right status code. Framework-agnostic |
| Sender | `src/sender.ts` | Signed POST with retry/backoff (30 s, then 5 min, max 3 attempts), a pluggable delivery log, injectable `fetch`/clock |

Runtime code uses only `node:crypto` and the global `fetch`/`Headers`. No dependencies. Dev dependencies: `vitest`, `typescript`, `@types/node`. Tests were run on Node v25.2.1 only (the SQL tests use `node:sqlite`).

```bash
npm install
npm test            # vitest run
npm run typecheck   # tsc --noEmit
```

To use it in a client project, copy `src/` in (or import it by path). Nothing here is on npm.

## The signing scheme (same as Opsflow's `lib/webhooks.ts`)

| | |
|---|---|
| Signed string | `${timestamp}.${rawBody}` |
| Algorithm | HMAC-SHA256, hex |
| `X-Webhook-Signature` | `sha256=<64 hex>` (several comma-separated values allowed, for secret rotation) |
| `X-Webhook-Timestamp` | ISO-8601 with a time zone, for example `2026-06-01T12:00:00.000Z` |
| `X-Webhook-Event` | event type (sender sets it) |
| `X-Webhook-Id` | stable event id (sender sets it; this is what the receiver dedupes on) |
| Replay window | default 5 minutes, rejected if older **or** further in the future than that |

## Receiving

```ts
import { handleWebhook, createMemoryStore } from "./src/index.js";

const store = createMemoryStore(); // single process only; see "Limits"

const result = await handleWebhook({
  rawBody,                 // the body exactly as received (string, Buffer or Uint8Array)
  headers,                 // Node req.headers, a plain object, or a Web Headers
  secret: process.env.WEBHOOK_SECRET!, // or [newSecret, oldSecret] during rotation
  store,
  handler: async ({ id, payload }) => { /* do the work; throw to make the sender retry */ },
  // scheme: "stripe",     // verify Stripe-Signature instead, dedupe on payload.id
});
// result = { status, body, reason?, error? }  -> send status and body; log reason/error yourself
```

What comes back:

| Situation | Status | Body | Handler runs? |
|---|---|---|---|
| Signature or timestamp header missing | 400 | `{error:"missing_signature"}` | no |
| Header or timestamp malformed | 400 | `{error:"malformed_signature"}` | no |
| Wrong signature, tampered body, expired, or too far in the future | 401 | `{error:"invalid_signature"}` (same body for all four) | no |
| Valid, but no usable event id | 400 | `{error:"missing_event_id"}` | no |
| First delivery of an id | 200 | `{status:"ok"}` | yes, once |
| Id already handled | 200 | `{status:"duplicate"}` | no |
| Same id currently being handled | 409 | `{status:"in_flight"}` | no |
| Handler threw | 500 | `{error:"handler_failed"}` (no error text) | it ran; the id is released so a retry re-runs it |
| Store unreachable | 500 | `{error:"store_error"}` | no |

`reason` (for your logs only) names the exact cause, for example `timestamp_too_old` or `signature_mismatch`.

### Express

```ts
// Register the raw parser for THIS route. Do not put express.json() in front of it.
app.post("/webhooks/orders", express.raw({ type: "application/json" }), async (req, res) => {
  const r = await handleWebhook({
    rawBody: req.body, // a Buffer, because of express.raw
    headers: req.headers,
    secret: process.env.WEBHOOK_SECRET!,
    store,
    handler: createOrder,
  });
  res.status(r.status).json(r.body);
});
```

### Next.js route handler (App Router)

```ts
export async function POST(req: Request) {
  const rawBody = await req.text(); // unparsed; do not call req.json() first
  const r = await handleWebhook({ rawBody, headers: req.headers, secret: process.env.WEBHOOK_SECRET!, store, handler: createOrder });
  return Response.json(r.body, { status: r.status });
}
```

Neither snippet was run inside Express or Next.js. The raw-body wiring they rely on is exercised against a plain `node:http` server in `test/e2e.test.ts`.

## Sending

```ts
import { deliverWithRetry, createMemoryLog } from "./src/index.js";

const log = createMemoryLog(); // replace with a writer to your own table
const result = await deliverWithRetry(
  { secret, log },
  "https://client.example/webhooks/orders",
  { id: "evt_100", type: "order.paid", payload: { orderId: "ord_42" } },
);
// attempt 1 -> wait 30 s -> attempt 2 -> wait 5 min -> attempt 3 -> give up
```

* The event id stays the same on every retry (that is what makes receiver-side dedupe work); each attempt is re-signed with a fresh timestamp.
* Every attempt writes one `DeliveryLogEntry`: status code, duration, a response snippet (2000 characters), the error, and `nextRetryAt`.
* Redirects are not followed; a 3xx counts as a failure. One attempt has a hard deadline (default 5 s, covering the body read).
* Serverless or queue style: call `sendOnce` per attempt and let a scheduler re-run entries whose `nextRetryAt` has passed (the shape Opsflow's cron sweep uses). `deliverWithRetry` sleeps in-process, so use it from a worker, not inside a request handler.

## SQL store (multi-instance dedupe)

```ts
import { CREATE_TABLE_SQL, createSqlStore } from "./src/index.js";
// run CREATE_TABLE_SQL once (it is the migration), then:
const store = createSqlStore({ query: (sql, params) => pool.query(sql, params) }); // pg-style
```

`query` is any `(sql, params) => Promise<{ rows }>` function. The `pool.query` line above matches the `pg` signature but was not run with `pg` here. The claim is `INSERT ... ON CONFLICT (id) DO NOTHING RETURNING id`, then a conditional `UPDATE ... RETURNING id` that reclaims a `failed` row or an `in_flight` row whose lock is older than `lockTimeoutMs` (default 5 minutes).

## Recipe: "orders are created twice"

1. Read the **raw** body (string or Buffer); never verify `JSON.stringify(parsedBody)`.
2. Verify the signature and the timestamp window; on failure answer 400/401 and stop (`handleWebhook` does steps 2 to 7).
3. Take the event id (`X-Webhook-Id`, else `payload.id`); no id means 400, because nothing can be deduped.
4. `store.begin(id)`: `done` answers 200 duplicate, `in_flight` answers 409 so the sender retries, `acquired` continues.
5. Run your handler. Make its own write safe too (a unique key on the order or payment id), because a crash between your write and `complete()` re-runs it after the lock timeout.
6. Handler throws: `store.fail(id)` and answer 500, so the sender's retry runs the handler again.
7. Handler returns: `store.complete(id)` and answer 200, so every later delivery of that id is a no-op.
8. Keep the handler short; push slow work onto a queue and acknowledge.
9. On the sending side keep one event id across all retries (`deliverWithRetry` does).
10. Prove it: deliver the same event twice and assert exactly one order (`test/e2e.test.ts` does this over real HTTP).

## "Signature keeps failing": what to check

Things the tests demonstrate:

* **The raw body must be byte-identical.** Re-serialising parsed JSON (even just adding indentation) makes a correct signature fail (`sign`, `stripe`, `receiver` and `e2e` tests).
* **Both sides' clocks matter.** A request outside the tolerance in either direction is rejected; `reason` tells you whether it was `timestamp_too_old` or `timestamp_in_future`.
* **The timestamp is part of the signed string.** Changing it, or the secret, gives `signature_mismatch`.
* **Header names are case-insensitive** on this side, and a Web `Headers` object works.
* **Secret rotation:** pass `[newSecret, oldSecret]`; senders may send several `sha256=` values.

Common causes not covered by a test here: a proxy or middleware that re-encodes or compresses the body, a trailing newline or whitespace in the secret from an env file, a test-mode secret used with live traffic.

## Differences from Opsflow's `lib/webhooks.ts`

| | Opsflow | webhook-kit |
|---|---|---|
| Signed string, algorithm, header format | `${ts}.${body}`, HMAC-SHA256, `sha256=<hex>` | identical (a pinned vector in `test/sign.test.ts` checks it) |
| Future timestamps | accepted (only stale ones are rejected) | rejected beyond the tolerance |
| Timestamp parsing | `Date.parse` (accepts anything it can) | strict ISO-8601 with a zone |
| Option name | `maxAgeMs` | `toleranceMs` (`maxAgeMs` accepted by the `verifySignature` wrapper) |
| Header with several signatures / several secrets | not supported | supported |
| Result | boolean | `{ ok, reason }` (plus a boolean `verifySignature` wrapper) |
| Event id header | none sent | `X-Webhook-Id` |
| Transport | `node:http(s)` with an SSRF-safe DNS lookup | global `fetch`, `redirect: "manual"`, **no private-network guard** |
| Retry | database rows plus a cron sweep (30 s / 5 min are floors) | in-process sleep (`deliverWithRetry`) or per-attempt `sendOnce` with `nextRetryAt` |
| Deadline | one hard deadline for the whole exchange | same idea (deadline race plus abort), response read capped at 4096 bytes |

## What this does NOT do, and what is not tested

* **Not tested against live Stripe.** `stripe.ts` follows https://docs.stripe.com/webhooks#verify-manually; its test vectors are generated from that algorithm inside the test file, not captured from Stripe. Only the signature check is implemented: no Stripe API calls, no thin-event parsing.
* **Not used in production.** It was built and tested locally. There is no load test, no soak test, and it has not run against a client system.
* **The in-memory store is single-process only.** Two server instances, or serverless invocations, do not share it. Use the SQL store (or your own `Store`) there.
* **The SQL store is verified on SQLite, plus one manual Postgres replay.** The automated tests run its exact statements on SQLite (`node:sqlite`). Separately, the statements recorded from one scenario were replayed once, by hand, on a local Postgres 16 in a temp table, and returned the same row counts. There is no automated Postgres test and no concurrent-claim test on Postgres. The lock is time-based, not fenced: a handler that outlives `lockTimeoutMs` can be re-run by a second worker.
* **No private-network guard in the sender.** If webhook URLs come from users, add an SSRF check before calling it (Opsflow's `lib/safe-url.ts` is the reference; not ported).
* **At-least-once, not exactly-once.** If `complete()` fails after your handler succeeded, the sender is told 500 and the handler can run again. Handlers need their own safe writes.
* **Handlers run before the response.** There is no built-in queue; slow handlers will hit the sender's timeout.
* **Constant-time comparison is by construction** (`crypto.timingSafeEqual`), not measured by a test.
* **Not covered:** body size limits, rate limiting, IP allow-listing, framework integration tests (Express, Next.js), Node versions other than v25.2.1.
