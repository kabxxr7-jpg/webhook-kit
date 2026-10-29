import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";
import { parseTimestamp, signPayload, signatureHeader, signedHeaders, verifySignature, verifyWebhook } from "../src/index.js";

const SECRET = "test-signing-secret-123";
const NOW = Date.parse("2026-06-01T12:00:00.000Z");
const iso = (ms: number) => new Date(ms).toISOString();
const BODY = '{"id":"evt_1","amount":4200}';

function signed(opts: { body?: string; ts?: string; secret?: string } = {}) {
  const ts = opts.ts ?? iso(NOW);
  const body = opts.body ?? BODY;
  return { timestamp: ts, body, signatureHeader: signatureHeader(opts.secret ?? SECRET, ts, body) };
}

describe("signPayload", () => {
  test("matches Opsflow's formula: HMAC-SHA256 hex over `${timestamp}.${body}`", () => {
    // Vector computed once with Opsflow's exact expression
    // crypto.createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")
    expect(signPayload(SECRET, "2026-01-01T00:00:00.000Z", '{"a":1}')).toBe(
      "de3193241778eded3c714a90af3ccb2a48692798bf2047c43aa02c84872dd232",
    );
    const expected = createHmac("sha256", SECRET).update(`${iso(NOW)}.${BODY}`).digest("hex");
    expect(signPayload(SECRET, iso(NOW), BODY)).toBe(expected);
  });

  test("a Uint8Array body signs to the same value as the equivalent string", () => {
    expect(signPayload(SECRET, iso(NOW), new TextEncoder().encode(BODY))).toBe(signPayload(SECRET, iso(NOW), BODY));
  });

  test("refuses an empty secret", () => {
    expect(() => signPayload("", iso(NOW), BODY)).toThrow(/non-empty/);
  });

  test("signedHeaders produces headers the verifier accepts", () => {
    const headers = signedHeaders({ secret: SECRET, body: BODY, now: NOW, eventType: "order.paid", eventId: "evt_1" });
    expect(headers["X-Webhook-Event"]).toBe("order.paid");
    expect(headers["X-Webhook-Id"]).toBe("evt_1");
    const verdict = verifyWebhook({
      secret: SECRET,
      timestamp: headers["X-Webhook-Timestamp"],
      signatureHeader: headers["X-Webhook-Signature"],
      body: BODY,
      nowMs: NOW,
    });
    expect(verdict).toEqual({ ok: true, timestampMs: NOW });
  });
});

describe("verifyWebhook", () => {
  test("accepts a valid request", () => {
    expect(verifyWebhook({ secret: SECRET, ...signed(), nowMs: NOW })).toEqual({ ok: true, timestampMs: NOW });
  });

  test("tamper: a changed body fails", () => {
    const s = signed();
    expect(verifyWebhook({ secret: SECRET, ...s, body: '{"id":"evt_1","amount":9999}', nowMs: NOW })).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  test("tamper: a body with whitespace changed by re-serialising fails (raw bytes matter)", () => {
    const s = signed();
    const reserialised = JSON.stringify(JSON.parse(BODY), null, 2);
    expect(reserialised).not.toBe(BODY);
    expect(verifyWebhook({ secret: SECRET, ...s, body: reserialised, nowMs: NOW }).ok).toBe(false);
  });

  test("tamper: a changed timestamp fails (it is part of the signed string)", () => {
    const s = signed();
    const result = verifyWebhook({ secret: SECRET, ...s, timestamp: iso(NOW + 1000), nowMs: NOW });
    expect(result).toEqual({ ok: false, reason: "signature_mismatch" });
  });

  test("tamper: flipping any single hex digit of the signature fails", () => {
    const s = signed();
    const sig = s.signatureHeader.slice("sha256=".length);
    for (let i = 0; i < sig.length; i += 1) {
      const flipped = sig.slice(0, i) + (sig[i] === "0" ? "1" : "0") + sig.slice(i + 1);
      const result = verifyWebhook({ secret: SECRET, ...s, signatureHeader: `sha256=${flipped}`, nowMs: NOW });
      expect(result).toEqual({ ok: false, reason: "signature_mismatch" });
    }
  });

  test("wrong secret fails", () => {
    expect(verifyWebhook({ secret: "another-secret", ...signed(), nowMs: NOW })).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  test("uppercase hex in the header is accepted (it is hex, not a different signature)", () => {
    const s = signed();
    const upper = `sha256=${s.signatureHeader.slice(7).toUpperCase()}`;
    expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: upper, nowMs: NOW }).ok).toBe(true);
  });

  describe("replay window", () => {
    test("expired: a correctly signed request older than the tolerance is rejected as too old", () => {
      const s = signed({ ts: iso(NOW - 6 * 60_000) });
      expect(verifyWebhook({ secret: SECRET, ...s, nowMs: NOW })).toEqual({ ok: false, reason: "timestamp_too_old" });
    });

    test("exactly at the tolerance is accepted; one millisecond beyond is not", () => {
      const edge = signed({ ts: iso(NOW - 5 * 60_000) });
      expect(verifyWebhook({ secret: SECRET, ...edge, nowMs: NOW }).ok).toBe(true);
      expect(verifyWebhook({ secret: SECRET, ...edge, nowMs: NOW + 1 })).toEqual({ ok: false, reason: "timestamp_too_old" });
    });

    test("future: a correctly signed request dated well ahead of the receiver clock is rejected", () => {
      const s = signed({ ts: iso(NOW + 10 * 60_000) });
      expect(verifyWebhook({ secret: SECRET, ...s, nowMs: NOW })).toEqual({ ok: false, reason: "timestamp_in_future" });
    });

    test("small clock skew inside the window is accepted", () => {
      const s = signed({ ts: iso(NOW + 30_000) });
      expect(verifyWebhook({ secret: SECRET, ...s, nowMs: NOW }).ok).toBe(true);
    });

    test("tolerance is configurable", () => {
      const s = signed({ ts: iso(NOW - 2 * 60_000) });
      expect(verifyWebhook({ secret: SECRET, ...s, nowMs: NOW, toleranceMs: 60_000 })).toEqual({
        ok: false,
        reason: "timestamp_too_old",
      });
      expect(verifyWebhook({ secret: SECRET, ...s, nowMs: NOW, toleranceMs: 3 * 60_000 }).ok).toBe(true);
    });

    test("a stale request with a WRONG signature reports the signature, not the age", () => {
      const s = signed({ ts: iso(NOW - 60 * 60_000), secret: "someone-else" });
      expect(verifyWebhook({ secret: SECRET, ...s, nowMs: NOW })).toEqual({ ok: false, reason: "signature_mismatch" });
    });

    test("a zero, negative or NaN tolerance is refused rather than silently disabling the check", () => {
      for (const toleranceMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
        expect(() => verifyWebhook({ secret: SECRET, ...signed(), toleranceMs, nowMs: NOW })).toThrow(RangeError);
      }
    });
  });

  describe("malformed input", () => {
    test("missing signature or timestamp", () => {
      const s = signed();
      expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: null, nowMs: NOW })).toEqual({ ok: false, reason: "missing_header" });
      expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: undefined, nowMs: NOW })).toEqual({ ok: false, reason: "missing_header" });
      expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: "", nowMs: NOW })).toEqual({ ok: false, reason: "missing_header" });
      expect(verifyWebhook({ secret: SECRET, ...s, timestamp: null, nowMs: NOW })).toEqual({ ok: false, reason: "missing_header" });
    });

    test.each([
      ["no scheme prefix", "a".repeat(64)],
      ["wrong scheme", `sha1=${"a".repeat(40)}`],
      ["short digest", `sha256=${"a".repeat(63)}`],
      ["long digest", `sha256=${"a".repeat(65)}`],
      ["non-hex digest", `sha256=${"z".repeat(64)}`],
      ["trailing comma", `sha256=${"a".repeat(64)},`],
      ["a good value next to a junk one", `sha256=${"a".repeat(64)}, junk`],
      ["whitespace only", "   "],
    ])("malformed signature header: %s", (_name, header) => {
      expect(verifyWebhook({ secret: SECRET, ...signed(), signatureHeader: header, nowMs: NOW })).toMatchObject({ ok: false });
      expect(verifyWebhook({ secret: SECRET, ...signed(), signatureHeader: header, nowMs: NOW })).toHaveProperty("reason");
    });

    test("malformed header reports malformed_header (not a mismatch)", () => {
      expect(verifyWebhook({ secret: SECRET, ...signed(), signatureHeader: "nonsense", nowMs: NOW })).toEqual({
        ok: false,
        reason: "malformed_header",
      });
    });

    test.each(["yesterday-ish", "1", "2026", "2026-06-01", "2026-06-01 12:00:00", "1780315200", "2026-06-01T12:00:00"])(
      "malformed timestamp: %s",
      (timestamp) => {
        const body = BODY;
        const header = signatureHeader(SECRET, timestamp, body);
        expect(verifyWebhook({ secret: SECRET, timestamp, body, signatureHeader: header, nowMs: NOW })).toEqual({
          ok: false,
          reason: "malformed_timestamp",
        });
      },
    );

    test("parseTimestamp accepts what toISOString and common ISO variants produce", () => {
      expect(parseTimestamp("2026-06-01T12:00:00.000Z")).toBe(NOW);
      expect(parseTimestamp("2026-06-01T12:00:00Z")).toBe(NOW);
      expect(parseTimestamp("2026-06-01T12:00:00.123456Z")).toBe(NOW + 123);
      expect(parseTimestamp("2026-06-01T17:30:00+05:30")).toBe(NOW);
    });
  });

  describe("multiple signatures and secrets", () => {
    test("a header with several signatures passes if any one is valid", () => {
      const good = signed().signatureHeader;
      const bad = `sha256=${"0".repeat(64)}`;
      const s = signed();
      expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: `${bad}, ${good}`, nowMs: NOW }).ok).toBe(true);
      expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: `${good},${bad}`, nowMs: NOW }).ok).toBe(true);
      expect(verifyWebhook({ secret: SECRET, ...s, signatureHeader: `${bad}, sha256=${"1".repeat(64)}`, nowMs: NOW }).ok).toBe(false);
    });

    test("secret rotation: a request signed with the old or the new secret passes while both are configured", () => {
      const oldReq = signed({ secret: "old-secret" });
      const newReq = signed({ secret: "new-secret" });
      for (const req of [oldReq, newReq]) {
        expect(verifyWebhook({ secret: ["new-secret", "old-secret"], ...req, nowMs: NOW }).ok).toBe(true);
      }
      expect(verifyWebhook({ secret: ["new-secret"], ...oldReq, nowMs: NOW }).ok).toBe(false);
    });

    test("an empty secret list or an empty secret in the list is a configuration error", () => {
      expect(() => verifyWebhook({ secret: [], ...signed(), nowMs: NOW })).toThrow(/at least one/);
      expect(() => verifyWebhook({ secret: ["ok", ""], ...signed(), nowMs: NOW })).toThrow(/non-empty/);
    });
  });
});

describe("verifySignature (Opsflow-compatible boolean wrapper)", () => {
  test("same parameter names as Opsflow, plus the maxAgeMs alias", () => {
    const s = signed({ ts: iso(NOW - 2 * 60_000) });
    expect(verifySignature({ secret: SECRET, ...s, nowMs: NOW })).toBe(true);
    expect(verifySignature({ secret: SECRET, ...s, nowMs: NOW, maxAgeMs: 60_000 })).toBe(false);
    expect(verifySignature({ secret: SECRET, ...s, nowMs: NOW, toleranceMs: 60_000 })).toBe(false);
    expect(verifySignature({ secret: SECRET, ...s, signatureHeader: null, nowMs: NOW })).toBe(false);
  });
});
