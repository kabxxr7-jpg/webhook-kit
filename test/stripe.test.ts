import { createHmac } from "node:crypto";
import { describe, expect, test } from "vitest";
import { verifyStripeSignature } from "../src/index.js";

// Vectors are built here, independently of the kit, straight from the documented algorithm
// (https://docs.stripe.com/webhooks#verify-manually): HMAC-SHA256(secret, `${t}.${rawBody}`) as hex.
// They are NOT captured from Stripe.
const SECRET = "whsec_test_secret_for_unit_tests";
const NOW_MS = Date.parse("2026-06-01T12:00:00.000Z");
const T = Math.floor(NOW_MS / 1000);
const BODY = '{"id":"evt_123","object":"event","type":"payment_intent.succeeded"}';

const v1 = (t: number | string, body: string, secret = SECRET) =>
  createHmac("sha256", secret).update(`${t}.${body}`).digest("hex");
const header = (t: number | string, ...sigs: string[]) => [`t=${t}`, ...sigs].join(",");

describe("verifyStripeSignature", () => {
  test("accepts a header built per the documented algorithm", () => {
    const h = header(T, `v1=${v1(T, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS })).toEqual({
      ok: true,
      timestampMs: T * 1000,
    });
  });

  test("a Uint8Array body gives the same result as the string", () => {
    const h = header(T, `v1=${v1(T, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: new TextEncoder().encode(BODY), nowMs: NOW_MS }).ok).toBe(true);
  });

  test("ignores the test-only v0 scheme when a valid v1 is present", () => {
    const h = header(T, `v1=${v1(T, BODY)}`, `v0=${"6".repeat(64)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS }).ok).toBe(true);
  });

  test("a header with only v0 is rejected (no downgrade to an ignored scheme)", () => {
    const h = header(T, `v0=${v1(T, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "malformed_header",
    });
  });

  test("multiple v1 signatures: passes if any one matches, in any position", () => {
    const wrong = `v1=${"0".repeat(64)}`;
    const right = `v1=${v1(T, BODY)}`;
    for (const h of [header(T, wrong, right), header(T, right, wrong), header(T, wrong, right, wrong)]) {
      expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS }).ok).toBe(true);
    }
    expect(verifyStripeSignature({ secret: SECRET, header: header(T, wrong, `v1=${"1".repeat(64)}`), body: BODY, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  test("secret rolling: one signature per active secret, verifier holding either secret accepts", () => {
    const h = header(T, `v1=${v1(T, BODY, "whsec_old")}`, `v1=${v1(T, BODY, "whsec_new")}`);
    expect(verifyStripeSignature({ secret: "whsec_old", header: h, body: BODY, nowMs: NOW_MS }).ok).toBe(true);
    expect(verifyStripeSignature({ secret: "whsec_new", header: h, body: BODY, nowMs: NOW_MS }).ok).toBe(true);
    expect(verifyStripeSignature({ secret: ["whsec_new", "whsec_old"], header: header(T, `v1=${v1(T, BODY, "whsec_old")}`), body: BODY, nowMs: NOW_MS }).ok).toBe(true);
    expect(verifyStripeSignature({ secret: "whsec_other", header: h, body: BODY, nowMs: NOW_MS }).ok).toBe(false);
  });

  test("tamper: changed body, changed timestamp and wrong secret all fail as mismatches", () => {
    const h = header(T, `v1=${v1(T, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY.replace("evt_123", "evt_124"), nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
    const shifted = header(T + 1, `v1=${v1(T, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: shifted, body: BODY, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
    expect(verifyStripeSignature({ secret: "whsec_wrong", header: h, body: BODY, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "signature_mismatch",
    });
  });

  test("a re-serialised body fails (Stripe needs the raw body)", () => {
    const h = header(T, `v1=${v1(T, BODY)}`);
    const pretty = JSON.stringify(JSON.parse(BODY), null, 2);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: pretty, nowMs: NOW_MS }).ok).toBe(false);
  });

  test("expired: validly signed but older than the default 5 minutes", () => {
    const old = T - 301;
    const h = header(old, `v1=${v1(old, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "timestamp_too_old",
    });
    const edge = T - 300;
    expect(verifyStripeSignature({ secret: SECRET, header: header(edge, `v1=${v1(edge, BODY)}`), body: BODY, nowMs: NOW_MS }).ok).toBe(true);
  });

  test("future: validly signed but dated beyond the tolerance ahead of the receiver clock", () => {
    const ahead = T + 600;
    const h = header(ahead, `v1=${v1(ahead, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS })).toEqual({
      ok: false,
      reason: "timestamp_in_future",
    });
  });

  test("tolerance is configurable and 0 is refused (Stripe: 0 would disable the recency check)", () => {
    const t = T - 120;
    const h = header(t, `v1=${v1(t, BODY)}`);
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS, toleranceSeconds: 60 })).toEqual({
      ok: false,
      reason: "timestamp_too_old",
    });
    expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS, toleranceSeconds: 600 }).ok).toBe(true);
    expect(() => verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS, toleranceSeconds: 0 })).toThrow(RangeError);
  });

  describe("malformed headers", () => {
    const good = `v1=${v1(T, BODY)}`;
    test("missing header", () => {
      for (const h of [null, undefined, ""]) {
        expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS })).toEqual({ ok: false, reason: "missing_header" });
      }
    });

    test.each([
      ["no timestamp", good],
      ["no signature", `t=${T}`],
      ["an element without =", `t=${T},${good},garbage`],
      ["two timestamps", `t=${T},t=${T},${good}`],
      ["empty string pieces", ","],
    ])("%s is malformed_header", (_name, h) => {
      expect(verifyStripeSignature({ secret: SECRET, header: h, body: BODY, nowMs: NOW_MS })).toEqual({
        ok: false,
        reason: "malformed_header",
      });
    });

    test.each(["abc", "1.5", "-5", "", "12345678901234567890"])("non-integer or oversize timestamp %j", (t) => {
      expect(verifyStripeSignature({ secret: SECRET, header: `t=${t},${good}`, body: BODY, nowMs: NOW_MS })).toEqual({
        ok: false,
        reason: "malformed_timestamp",
      });
    });

    test("a v1 value that is not 64 hex characters never matches", () => {
      for (const sig of ["", "abc", "g".repeat(64), "a".repeat(63)]) {
        expect(verifyStripeSignature({ secret: SECRET, header: `t=${T},v1=${sig}`, body: BODY, nowMs: NOW_MS })).toEqual({
          ok: false,
          reason: "signature_mismatch",
        });
      }
    });
  });

  test("an empty secret is a configuration error", () => {
    expect(() => verifyStripeSignature({ secret: "", header: header(T, `v1=${v1(T, BODY)}`), body: BODY, nowMs: NOW_MS })).toThrow(/non-empty/);
  });
});
