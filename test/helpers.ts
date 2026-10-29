import { DatabaseSync } from "node:sqlite";
import { createMemoryStore, createSqlStore, createTableSql, type Query, type Store } from "../src/index.js";

export const SECRET = "test-signing-secret-123";
export const NOW = Date.parse("2026-06-01T12:00:00.000Z");

/** A clock you move by hand. */
export function makeClock(start = NOW) {
  let t = start;
  return {
    now: () => t,
    advance(ms: number) {
      t += ms;
    },
    set(ms: number) {
      t = ms;
    },
  };
}

export interface Deferred<T = void> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

export function deferred<T = void>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/**
 * Runs the SQL store's statements on SQLite (node:sqlite) so the claim logic is exercised without a
 * server. `$1` placeholders become `?1`, Dates become ISO strings (same width, so string comparison
 * orders them). This checks the logic and the statement shapes, NOT Postgres itself.
 */
export function sqliteQuery(table = "webhook_events") {
  const db = new DatabaseSync(":memory:");
  db.exec(createTableSql(table));
  const query: Query = async (sql, params) => {
    const text = sql.replace(/\$(\d+)/g, "?$1");
    const values = params.map((p) => (p instanceof Date ? p.toISOString() : (p ?? null))) as Array<string | number | null>;
    const rows = db.prepare(text).all(...values) as Array<Record<string, unknown>>;
    return { rows };
  };
  return { db, query };
}

export type StoreFactory = (now?: () => number) => Store;

export const storeFactories: Array<[string, StoreFactory]> = [
  ["memory", (now) => (now ? createMemoryStore({ now }) : createMemoryStore())],
  [
    "sql (sqlite)",
    (now) => {
      const { query } = sqliteQuery();
      return now ? createSqlStore({ query, now }) : createSqlStore({ query });
    },
  ],
];
