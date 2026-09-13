import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { validateWindowsSecurity4663GenuineMatchReceipt } from "./check-windows-security-4663-genuine-match-receipt.mjs";

const checker = fileURLToPath(new URL(
  "./check-windows-security-4663-genuine-match-receipt.mjs", import.meta.url));
const trueFields = [
  "readinessApplied", "resultSlotPrepared", "approvalWrittenAndChecked",
  "inertTriggerCompleted", "triggerSettlementCompleted",
  "serviceStartedOnce", "serviceStopped", "startupModeRestored",
  "resultExternallyChecked", "genuineMatchValidated", "resultConsumed",
  "approvalAbsent", "resultAbsent", "rollbackCompleted"
];
const falseFields = [
  "rawEventContentRetained", "continuousCollectionEnabled", "retryEnabled",
  "pollingEnabled", "telemetryEnabled", "transportEnabled", "ipcEnabled",
  "inboundListenerEnabled", "commandChannelEnabled", "responseActionEnabled"
];

function receipt() {
  return {
    ok: true,
    command: "genuine-match-exercise",
    result: {
      checkpoint: "gate-c2g-security-4663-genuine-match",
      ...Object.fromEntries(trueFields.map((field) => [field, true])),
      triggerSettlementMilliseconds: 2_000,
      readState: "match",
      eventsRead: 1,
      maximumEventsRead: 1,
      maximumQueries: 1,
      maximumQueryMilliseconds: 2_000,
      maximumTriggerWindowSeconds: 10,
      ...Object.fromEntries(falseFields.map((field) => [field, false]))
    }
  };
}

describe("C2g genuine-match receipt checker", () => {
  it("accepts only one fixed-settlement privacy-safe genuine match", () => {
    const checked = validateWindowsSecurity4663GenuineMatchReceipt(receipt());
    assert.equal(checked.result.readState, "match");
    assert.equal(checked.result.eventsRead, 1);
    assert.equal(Object.isFrozen(checked), true);
    assert.equal(Object.isFrozen(checked.result), true);
  });

  it("rejects root, schema and genuine-match drift", () => {
    for (const value of [null, [], "x", { ...receipt(), extra: true },
      { ...receipt(), ok: false }, { ...receipt(), command: "live-exercise" }]) {
      assert.throws(
        () => validateWindowsSecurity4663GenuineMatchReceipt(value),
        /SENSOR_C2G_SECURITY_4663_RECEIPT_INPUT_INVALID/);
    }
    const mutations = [];
    const missing = receipt(); delete missing.result.genuineMatchValidated;
    const extra = receipt(); extra.result.path = "forbidden";
    mutations.push(missing, extra);
    for (const field of trueFields) {
      const value = receipt(); value.result[field] = false; mutations.push(value);
    }
    for (const field of falseFields) {
      const value = receipt(); value.result[field] = true; mutations.push(value);
    }
    for (const [field, value] of [
      ["checkpoint", "gate-c2f-security-4663-live-one-shot"],
      ["triggerSettlementMilliseconds", 1_999],
      ["readState", "no-match"], ["eventsRead", 0],
      ["maximumEventsRead", 2], ["maximumQueries", 2],
      ["maximumQueryMilliseconds", 1_999],
      ["maximumTriggerWindowSeconds", 11]
    ]) {
      const mutated = receipt(); mutated.result[field] = value; mutations.push(mutated);
    }
    for (const value of mutations) {
      assert.throws(
        () => validateWindowsSecurity4663GenuineMatchReceipt(value),
        /SENSOR_C2G_SECURITY_4663_RECEIPT_RESULT_INVALID/);
    }
  });

  it("rejects prototype, symbol, accessor and descriptor tricks", () => {
    const inherited = Object.create({ extra: true }); Object.assign(inherited, receipt());
    const symbolic = receipt(); symbolic[Symbol("extra")] = true;
    const accessor = receipt(); Object.defineProperty(
      accessor.result, "eventsRead", { get: () => 1, enumerable: true });
    const resultInherited = receipt(); resultInherited.result = Object.assign(
      Object.create({ extra: true }), resultInherited.result);
    const resultSymbolic = receipt(); resultSymbolic.result[Symbol("extra")] = true;
    const readOnly = receipt(); Object.defineProperty(
      readOnly.result, "eventsRead", { value: 1, enumerable: true, writable: false });
    const nonEnumerable = receipt(); Object.defineProperty(
      nonEnumerable.result, "hidden", { value: true });
    for (const value of [inherited, symbolic, accessor, resultInherited,
      resultSymbolic, readOnly, nonEnumerable]) {
      assert.throws(() => validateWindowsSecurity4663GenuineMatchReceipt(value));
    }
  });

  it("CLI binds canonical input to one external SHA-256", () => {
    const text = JSON.stringify(receipt());
    const sha = createHash("sha256").update(text, "utf8").digest("hex");
    const ok = spawnSync(process.execPath,
      [checker, "--expected-sha256", sha], { input: text, encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(JSON.parse(ok.stdout), {
      ok: true,
      purpose: "project15.windows-security-4663-genuine-match-receipt-check.v1",
      checkpoint: "gate-c2g-security-4663-genuine-match",
      triggerSettlementMilliseconds: 2_000,
      readState: "match",
      eventsRead: 1,
      maximumEventsRead: 1,
      maximumQueries: 1,
      maximumQueryMilliseconds: 2_000,
      maximumTriggerWindowSeconds: 10,
      privacyBoundaryFieldsValidated: true,
      rollbackReceiptValidated: true
    });
    for (const args of [[], ["--expected-sha256", sha, "extra"]]) {
      const bad = spawnSync(process.execPath, [checker, ...args],
        { input: text, encoding: "utf8" });
      assert.notEqual(bad.status, 0);
      assert.equal(bad.stderr,
        "SENSOR_C2G_SECURITY_4663_RECEIPT_ARGUMENT_INVALID\n");
    }
    const wrongHash = spawnSync(process.execPath,
      [checker, "--expected-sha256", "0".repeat(64)],
      { input: text, encoding: "utf8" });
    assert.equal(wrongHash.stderr,
      "SENSOR_C2G_SECURITY_4663_RECEIPT_HASH_MISMATCH\n");
  });

  it("CLI rejects oversized, malformed and noncanonical receipts", () => {
    const valid = JSON.stringify(receipt());
    for (const [text, expected] of [
      ["x".repeat(16_385), "SENSOR_C2G_SECURITY_4663_RECEIPT_SIZE_INVALID\n"],
      ["{", "SENSOR_C2G_SECURITY_4663_RECEIPT_JSON_INVALID\n"],
      [JSON.stringify(receipt(), null, 2),
        "SENSOR_C2G_SECURITY_4663_RECEIPT_CANONICAL_INVALID\n"],
      [`${valid}\n`, "SENSOR_C2G_SECURITY_4663_RECEIPT_CANONICAL_INVALID\n"]
    ]) {
      const sha = createHash("sha256").update(text, "utf8").digest("hex");
      const bad = spawnSync(process.execPath,
        [checker, "--expected-sha256", sha], { input: text, encoding: "utf8" });
      assert.notEqual(bad.status, 0);
      assert.equal(bad.stderr, expected);
    }
    const invalidUtf8 = Buffer.from([0xff]);
    const invalidUtf8Sha = createHash("sha256").update(invalidUtf8).digest("hex");
    const badEncoding = spawnSync(process.execPath,
      [checker, "--expected-sha256", invalidUtf8Sha], { input: invalidUtf8 });
    assert.equal(badEncoding.stderr.toString(),
      "SENSOR_C2G_SECURITY_4663_RECEIPT_ENCODING_INVALID\n");
  });
});
