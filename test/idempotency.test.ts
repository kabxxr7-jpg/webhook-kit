import { describe, expect, test } from "vitest";
import { CREATE_TABLE_SQL, DEFAULT_LOCK_TIMEOUT_MS, createSqlStore, createTableSql } from "../src/index.js";
import { makeClock, sqliteQuery, storeFactories } from "./helpers.js";

describe.each(storeFactories)("store contract: %s", (_name, make) => {
  test("a new id is acquired; a second claim while it is in flight is refused", async () => {
    const store = make();
    expect(await store.begin("evt_1")).toBe("acquired");
    expect(await store.begin("evt_1")).toBe("in_flight");
  });

  test("duplicate event: once completed, every later delivery of the id is reported done", async () => {
    const store = make();
    expect(await store.begin("evt_1")).toBe("acquired");
    await store.complete("evt_1");
    expect(await store.begin("evt_1")).toBe("done");
    expect(await store.begin("evt_1")).toBe("done");
  });

  test("completing twice is harmless", async () => {
    const store = make();
    await store.begin("evt_1");
    await store.complete("evt_1");
    await store.complete("evt_1");
    expect(await store.begin("evt_1")).toBe("done");
  });

  test("handler failure: a failed id can be claimed again, and then completed", async () => {
    const store = make();
    expect(await store.begin("evt_1")).toBe("acquired");
    await store.fail("evt_1", "boom");
    expect(await store.begin("evt_1")).toBe("acquired");
    expect(await store.begin("evt_1")).toBe("in_flight");
    await store.complete("evt_1");
    expect(await store.begin("evt_1")).toBe("done");
  });

  test("a stray fail() on a finished id does not undo it", async () => {
    const store = make();
    await store.begin("evt_1");
    await store.complete("evt_1");
    await store.fail("evt_1", "late");
    expect(await store.begin("evt_1")).toBe("done");
  });

  test("ids are independent", async () => {
    const store = make();
    expect(await store.begin("a")).toBe("acquired");
    expect(await store.begin("b")).toBe("acquired");
    await store.complete("a");
    expect(await store.begin("b")).toBe("in_flight");
    expect(await store.begin("a")).toBe("done");
  });

  test("concurrent duplicates: of 25 simultaneous claims on one id exactly one is acquired", async () => {
    const store = make();
    const results = await Promise.all(Array.from({ length: 25 }, () => store.begin("evt_race")));
    expect(results.filter((r) => r === "acquired")).toHaveLength(1);
    expect(results.filter((r) => r === "in_flight")).toHaveLength(24);
  });

  test("concurrent retries of a failed id: exactly one wins the re-run", async () => {
    const store = make();
    await store.begin("evt_race");
    await store.fail("evt_race", "boom");
    const results = await Promise.all(Array.from({ length: 10 }, () => store.begin("evt_race")));
    expect(results.filter((r) => r === "acquired")).toHaveLength(1);
  });

  test("a crashed worker's in-flight claim is reclaimed only after the lock timeout", async () => {
    const clock = makeClock();
    const store = make(clock.now);
    expect(await store.begin("evt_1", { lockTimeoutMs: 60_000 })).toBe("acquired");

    clock.advance(60_000); // exactly the timeout: still held
    expect(await store.begin("evt_1", { lockTimeoutMs: 60_000 })).toBe("in_flight");

    clock.advance(1); // one millisecond past it: reclaimable
    expect(await store.begin("evt_1", { lockTimeoutMs: 60_000 })).toBe("acquired");
    expect(await store.begin("evt_1", { lockTimeoutMs: 60_000 })).toBe("in_flight");
  });

  test("the default lock timeout is 5 minutes", async () => {
    expect(DEFAULT_LOCK_TIMEOUT_MS).toBe(5 * 60_000);
    const clock = makeClock();
    const store = make(clock.now);
    await store.begin("evt_1");
    clock.advance(5 * 60_000);
    expect(await store.begin("evt_1")).toBe("in_flight");
    clock.advance(1);
    expect(await store.begin("evt_1")).toBe("acquired");
  });

  test("a finished id is never reclaimed, however old", async () => {
    const clock = makeClock();
    const store = make(clock.now);
    await store.begin("evt_1");
    await store.complete("evt_1");
    clock.advance(365 * 24 * 3600_000);
    expect(await store.begin("evt_1")).toBe("done");
  });
});

describe("SQL store specifics (SQLite stand-in)", () => {
  test("records attempts, status and the last error in the table", async () => {
    const clock = makeClock();
    const { db, query } = sqliteQuery();
    const store = createSqlStore({ query, now: clock.now });

    await store.begin("evt_1");
    await store.fail("evt_1", "upstream 503");
    const failed = db.prepare("SELECT status, attempts, last_error FROM webhook_events WHERE id = ?").get("evt_1");
    expect(failed).toMatchObject({ status: "failed", attempts: 1, last_error: "upstream 503" });

    await store.begin("evt_1");
    await store.complete("evt_1");
    const done = db.prepare("SELECT status, attempts, last_error, finished_at FROM webhook_events WHERE id = ?").get("evt_1");
    expect(done).toMatchObject({ status: "done", attempts: 2, last_error: null });
    expect(done?.["finished_at"]).toBe(new Date(clock.now()).toISOString());
  });

  test("a reclaimed stale claim counts as another attempt", async () => {
    const clock = makeClock();
    const { db, query } = sqliteQuery();
    const store = createSqlStore({ query, now: clock.now });
    await store.begin("evt_1");
    clock.advance(DEFAULT_LOCK_TIMEOUT_MS + 1);
    expect(await store.begin("evt_1")).toBe("acquired");
    expect(db.prepare("SELECT attempts FROM webhook_events WHERE id = ?").get("evt_1")).toMatchObject({ attempts: 2 });
  });

  test("uses a custom table name and refuses anything that is not a plain identifier", async () => {
    const { db, query } = sqliteQuery("orders_webhooks");
    const store = createSqlStore({ query, table: "orders_webhooks" });
    expect(await store.begin("evt_1")).toBe("acquired");
    expect(db.prepare("SELECT count(*) AS n FROM orders_webhooks").get()).toMatchObject({ n: 1 });

    for (const table of ["x; DROP TABLE y", "a b", "1abc", "", "a-b"]) {
      expect(() => createSqlStore({ query, table })).toThrow(/plain identifier/);
      expect(() => createTableSql(table)).toThrow(/plain identifier/);
    }
  });

  test("every statement uses placeholders: the event id never reaches the SQL text", async () => {
    const seen: string[] = [];
    const { query } = sqliteQuery();
    const store = createSqlStore({
      query: async (sql, params) => {
        seen.push(sql);
        return query(sql, params);
      },
    });
    const hostile = "x'); DROP TABLE webhook_events; --";
    await store.begin(hostile);
    await store.complete(hostile);
    await store.begin(hostile);
    expect(seen.length).toBeGreaterThan(0);
    for (const sql of seen) expect(sql).not.toContain("DROP TABLE");
    expect(await store.begin(hostile)).toBe("done");
  });

  test("CREATE_TABLE_SQL is the migration for the default table", () => {
    expect(CREATE_TABLE_SQL).toContain("CREATE TABLE IF NOT EXISTS webhook_events");
    expect(CREATE_TABLE_SQL).toContain("id          text PRIMARY KEY");
    expect(CREATE_TABLE_SQL).toContain("'in_flight', 'done', 'failed'");
  });
});
