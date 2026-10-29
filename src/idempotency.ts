/**
 * Event-id dedupe. A delivery is in one of three states:
 *   in_flight  a worker holds it and is running the handler
 *   done       the handler finished; further deliveries of this id are duplicates
 *   failed     the handler threw; the next delivery may run it again
 *
 * `begin` is the only atomic step: it either hands the caller the right to run the handler
 * ("acquired") or says why not.
 */
export type BeginResult = "acquired" | "done" | "in_flight";

export interface Store {
  /**
   * Try to claim `id`. Claims a fresh id, a `failed` id, and an `in_flight` id whose lock is older
   * than `lockTimeoutMs` (a crashed worker must not block an event forever).
   */
  begin(id: string, options?: { lockTimeoutMs?: number }): Promise<BeginResult>;
  complete(id: string): Promise<void>;
  fail(id: string, error?: string): Promise<void>;
}

export const DEFAULT_LOCK_TIMEOUT_MS = 5 * 60_000;

/**
 * Single-process only. Fine for tests, local development and a single long-lived server; useless
 * across serverless invocations or multiple instances (use the SQL store there).
 */
export function createMemoryStore(options: { now?: () => number } = {}): Store {
  const now = options.now ?? Date.now;
  const rows = new Map<string, { status: "in_flight" | "done" | "failed"; lockedAt: number }>();

  return {
    async begin(id, opts = {}) {
      // No await between the read and the write: in one process this is atomic.
      const lockTimeoutMs = opts.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
      const row = rows.get(id);
      if (!row) {
        rows.set(id, { status: "in_flight", lockedAt: now() });
        return "acquired";
      }
      if (row.status === "done") return "done";
      if (row.status === "failed" || now() - row.lockedAt > lockTimeoutMs) {
        rows.set(id, { status: "in_flight", lockedAt: now() });
        return "acquired";
      }
      return "in_flight";
    },
    async complete(id) {
      const row = rows.get(id);
      if (row?.status === "in_flight") rows.set(id, { status: "done", lockedAt: row.lockedAt });
    },
    async fail(id) {
      const row = rows.get(id);
      if (row?.status === "in_flight") rows.set(id, { status: "failed", lockedAt: row.lockedAt });
    },
  };
}

/** `query` is any Postgres client's `(text, values)` function (pg, postgres.js wrapper, Prisma `$queryRawUnsafe`...). */
export type Query = (sql: string, params: unknown[]) => Promise<{ rows: Array<Record<string, unknown>> }>;

/** Run once (migration). Postgres dialect. */
export function createTableSql(table = "webhook_events"): string {
  if (!/^[a-z_][a-z0-9_]*$/i.test(table)) throw new Error("table must be a plain identifier");
  return `CREATE TABLE IF NOT EXISTS ${table} (
  id          text PRIMARY KEY,
  status      text NOT NULL CHECK (status IN ('in_flight', 'done', 'failed')),
  attempts    integer NOT NULL DEFAULT 1,
  locked_at   timestamptz NOT NULL,
  finished_at timestamptz,
  last_error  text
)`;
}

export const CREATE_TABLE_SQL = createTableSql();

/**
 * Reference implementation on a `webhook_events` table (see CREATE_TABLE_SQL). Each statement is
 * atomic on its own; the claim is two of them:
 *   1. INSERT ... ON CONFLICT (id) DO NOTHING RETURNING id   -> a returned row means "first delivery"
 *   2. otherwise UPDATE ... WHERE failed OR stale lock RETURNING id -> a returned row means "reclaimed"
 * If neither returns a row the id is `done`, or held by a live worker: one SELECT tells which.
 *
 * Limit: the lock is time-based, not fenced. A handler that runs longer than `lockTimeoutMs` can be
 * reclaimed by a second worker, so keep handlers short (enqueue the slow work) or raise the timeout.
 */
export function createSqlStore(options: { query: Query; now?: () => number; table?: string }): Store {
  const { query } = options;
  const now = options.now ?? Date.now;
  const table = options.table ?? "webhook_events";
  if (!/^[a-z_][a-z0-9_]*$/i.test(table)) throw new Error("table must be a plain identifier");

  return {
    async begin(id, opts = {}) {
      const lockTimeoutMs = opts.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS;
      const at = new Date(now());

      const inserted = await query(
        `INSERT INTO ${table} (id, status, attempts, locked_at) VALUES ($1, 'in_flight', 1, $2) ON CONFLICT (id) DO NOTHING RETURNING id`,
        [id, at],
      );
      if (inserted.rows.length > 0) return "acquired";

      const reclaimed = await query(
        `UPDATE ${table} SET status = 'in_flight', attempts = attempts + 1, locked_at = $2, finished_at = NULL ` +
          `WHERE id = $1 AND (status = 'failed' OR (status = 'in_flight' AND locked_at < $3)) RETURNING id`,
        [id, at, new Date(now() - lockTimeoutMs)],
      );
      if (reclaimed.rows.length > 0) return "acquired";

      const current = await query(`SELECT status FROM ${table} WHERE id = $1`, [id]);
      return current.rows[0]?.["status"] === "done" ? "done" : "in_flight";
    },
    async complete(id) {
      await query(
        `UPDATE ${table} SET status = 'done', finished_at = $2, last_error = NULL WHERE id = $1 AND status = 'in_flight'`,
        [id, new Date(now())],
      );
    },
    async fail(id, error) {
      await query(
        `UPDATE ${table} SET status = 'failed', finished_at = $2, last_error = $3 WHERE id = $1 AND status = 'in_flight'`,
        [id, new Date(now()), error ?? null],
      );
    },
  };
}
