import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { validateWindowsSecurity4663LiveExerciseReceipt } from "./check-windows-security-4663-live-exercise-receipt.mjs";

const checker = fileURLToPath(new URL("./check-windows-security-4663-live-exercise-receipt.mjs", import.meta.url));
const trueFields = ["readinessApplied", "resultSlotPrepared", "approvalWrittenAndChecked", "inertTriggerCompleted", "serviceStartedOnce", "serviceStopped", "startupModeRestored", "resultExternallyChecked", "resultConsumed", "approvalAbsent", "resultAbsent", "rollbackCompleted"];
const falseFields = ["rawEventContentRetained", "continuousCollectionEnabled", "retryEnabled", "pollingEnabled", "telemetryEnabled", "transportEnabled", "inboundListenerEnabled", "commandChannelEnabled", "responseActionEnabled"];

function receipt(readState = "match") {
  const result = {
    checkpoint: "gate-c2f-security-4663-live-one-shot",
    ...Object.fromEntries(trueFields.map((field) => [field, true])),
    readState,
    eventsRead: readState === "match" ? 1 : 0,
    maximumEventsRead: 1,
    ...Object.fromEntries(falseFields.map((field) => [field, false]))
  };
  return { ok: true, command: "live-exercise", result };
}

describe("C2f privacy-safe live-exercise receipt checker", () => {
  it("accepts only the exact successful bounded lifecycle for every read state", () => {
    for (const state of ["match", "no-match", "access-denied", "source-unavailable", "query-failed"]) {
      const checked = validateWindowsSecurity4663LiveExerciseReceipt(receipt(state));
      assert.equal(checked.result.readState, state);
      assert.equal(Object.isFrozen(checked), true);
      assert.equal(Object.isFrozen(checked.result), true);
    }
  });

  it("rejects root and result schema drift", () => {
    for (const value of [null, [], "x", { ...receipt(), extra: true }, { ...receipt(), ok: false }, { ...receipt(), command: "plan" }]) {
      assert.throws(() => validateWindowsSecurity4663LiveExerciseReceipt(value), /SENSOR_C2F_SECURITY_4663_LIVE_RECEIPT_INPUT_INVALID/);
    }
    const missing = receipt(); delete missing.result.approvalAbsent;
    const extra = receipt(); extra.result.path = "secret";
    for (const value of [missing, extra]) assert.throws(() => validateWindowsSecurity4663LiveExerciseReceipt(value), /SENSOR_C2F_SECURITY_4663_LIVE_RECEIPT_RESULT_INVALID/);
  });

  it("rejects incomplete lifecycle, authority drift and fabricated event counts", () => {
    for (const field of trueFields) { const value = receipt(); value.result[field] = false; assert.throws(() => validateWindowsSecurity4663LiveExerciseReceipt(value)); }
    for (const field of falseFields) { const value = receipt(); value.result[field] = true; assert.throws(() => validateWindowsSecurity4663LiveExerciseReceipt(value)); }
    for (const value of [receipt("unknown"), receipt("match"), receipt("no-match")]) {
      if (value.result.readState === "match") value.result.eventsRead = 0;
      else if (value.result.readState === "no-match") value.result.eventsRead = 1;
      assert.throws(() => validateWindowsSecurity4663LiveExerciseReceipt(value));
    }
  });

  it("rejects prototype, symbol, accessor and descriptor tricks", () => {
    const inherited = Object.create({ extra: true }); Object.assign(inherited, receipt());
    const symbolic = receipt(); symbolic[Symbol("extra")] = true;
    const accessor = receipt(); Object.defineProperty(accessor.result, "eventsRead", { get: () => 1, enumerable: true });
    const nonEnumerable = receipt(); Object.defineProperty(nonEnumerable.result, "hidden", { value: true });
    for (const value of [inherited, symbolic, accessor, nonEnumerable]) assert.throws(() => validateWindowsSecurity4663LiveExerciseReceipt(value));
  });

  it("CLI requires one external SHA-256 and emits a bounded data-only check", () => {
    const text = JSON.stringify(receipt());
    const sha = createHash("sha256").update(text, "utf8").digest("hex");
    const ok = spawnSync(process.execPath, [checker, "--expected-sha256", sha], { input: text, encoding: "utf8" });
    assert.equal(ok.status, 0, ok.stderr);
    assert.deepEqual(JSON.parse(ok.stdout), {
      ok: true,
      purpose: "project15.windows-security-4663-live-exercise-receipt-check.v1",
      checkpoint: "gate-c2f-security-4663-live-one-shot",
      readState: "match",
      eventsRead: 1,
      maximumEventsRead: 1,
      privacyBoundariesVerified: true,
      rollbackVerified: true
    });
    for (const args of [[], ["--expected-sha256", "0".repeat(64)], ["--expected-sha256", sha, "extra"]]) {
      const bad = spawnSync(process.execPath, [checker, ...args], { input: text, encoding: "utf8" });
      assert.notEqual(bad.status, 0);
      assert.match(bad.stderr, /^SENSOR_C2F_SECURITY_4663_LIVE_RECEIPT_[A-Z0-9_]+\n$/);
    }
  });

  it("CLI rejects oversized, malformed, noncanonical and newline-rewritten receipts", () => {
    const valid = JSON.stringify(receipt());
    const cases = ["x".repeat(16_385), "{", JSON.stringify(receipt(), null, 2), `${valid}\n`];
    for (const text of cases) {
      const sha = createHash("sha256").update(text, "utf8").digest("hex");
      const bad = spawnSync(process.execPath, [checker, "--expected-sha256", sha], { input: text, encoding: "utf8" });
      assert.notEqual(bad.status, 0);
    }
  });
});
