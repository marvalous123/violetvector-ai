import { createHash, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const purpose = "project15.windows-security-4663-genuine-match-receipt-check.v1";
const checkpoint = "gate-c2g-security-4663-genuine-match";
const maximumReceiptBytes = 16_384;
const rootKeys = Object.freeze(["ok", "command", "result"]);
const lifecycleTrueFields = Object.freeze([
  "readinessApplied", "resultSlotPrepared", "approvalWrittenAndChecked",
  "inertTriggerCompleted", "triggerSettlementCompleted",
  "serviceStartedOnce", "serviceStopped", "startupModeRestored",
  "resultExternallyChecked", "genuineMatchValidated", "resultConsumed",
  "approvalAbsent", "resultAbsent", "rollbackCompleted"
]);
const boundaryFalseFields = Object.freeze([
  "rawEventContentRetained", "continuousCollectionEnabled", "retryEnabled",
  "pollingEnabled", "telemetryEnabled", "transportEnabled", "ipcEnabled",
  "inboundListenerEnabled", "commandChannelEnabled", "responseActionEnabled"
]);
const resultKeys = Object.freeze([
  "checkpoint", ...lifecycleTrueFields, "triggerSettlementMilliseconds",
  "readState", "eventsRead", "maximumEventsRead", "maximumQueries",
  "maximumQueryMilliseconds", "maximumTriggerWindowSeconds",
  ...boundaryFalseFields
]);

function invalid(code) { throw new Error(code); }

function requireExactPlainRecord(value, keys, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.getOwnPropertySymbols(value).length !== 0) invalid(code);
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== keys.length ||
      names.some((name, index) => name !== keys[index])) invalid(code);
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !("value" in descriptor) || descriptor.get ||
        descriptor.set || !descriptor.enumerable || !descriptor.configurable ||
        !descriptor.writable) invalid(code);
  }
}

export function validateWindowsSecurity4663GenuineMatchReceipt(value) {
  requireExactPlainRecord(value, rootKeys,
    "SENSOR_C2G_SECURITY_4663_RECEIPT_INPUT_INVALID");
  if (value.ok !== true || value.command !== "genuine-match-exercise") {
    invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_INPUT_INVALID");
  }
  requireExactPlainRecord(value.result, resultKeys,
    "SENSOR_C2G_SECURITY_4663_RECEIPT_RESULT_INVALID");
  const result = value.result;
  if (result.checkpoint !== checkpoint ||
      result.triggerSettlementMilliseconds !== 2_000 ||
      result.readState !== "match" || result.eventsRead !== 1 ||
      result.maximumEventsRead !== 1 || result.maximumQueries !== 1 ||
      result.maximumQueryMilliseconds !== 2_000 ||
      result.maximumTriggerWindowSeconds !== 10 ||
      lifecycleTrueFields.some((field) => result[field] !== true) ||
      boundaryFalseFields.some((field) => result[field] !== false)) {
    invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_RESULT_INVALID");
  }
  const frozenResult = Object.freeze(Object.fromEntries(
    resultKeys.map((key) => [key, result[key]])));
  return Object.freeze({
    ok: true,
    command: "genuine-match-exercise",
    result: frozenResult
  });
}

async function readBoundedStdin() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > maximumReceiptBytes) {
      invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_SIZE_INVALID");
    }
    chunks.push(bytes);
  }
  return Buffer.concat(chunks, total);
}

async function runCli() {
  if (process.argv.length !== 4 || process.argv[2] !== "--expected-sha256" ||
      !/^[0-9a-f]{64}$/.test(process.argv[3])) {
    invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_ARGUMENT_INVALID");
  }
  const bytes = await readBoundedStdin();
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_ENCODING_INVALID"); }
  if (!text || text.endsWith("\n") || text.endsWith("\r")) {
    invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_CANONICAL_INVALID");
  }
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_JSON_INVALID"); }
  const checked = validateWindowsSecurity4663GenuineMatchReceipt(parsed);
  if (JSON.stringify(checked) !== text) {
    invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_CANONICAL_INVALID");
  }
  const actual = createHash("sha256").update(bytes).digest();
  const expected = Buffer.from(process.argv[3], "hex");
  if (!timingSafeEqual(actual, expected)) {
    invalid("SENSOR_C2G_SECURITY_4663_RECEIPT_HASH_MISMATCH");
  }
  process.stdout.write(`${JSON.stringify({
    ok: true,
    purpose,
    checkpoint,
    triggerSettlementMilliseconds: 2_000,
    readState: "match",
    eventsRead: 1,
    maximumEventsRead: 1,
    maximumQueries: 1,
    maximumQueryMilliseconds: 2_000,
    maximumTriggerWindowSeconds: 10,
    privacyBoundaryFieldsValidated: true,
    rollbackReceiptValidated: true
  })}\n`);
}

const isMain = process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runCli().catch((error) => {
    const code = error instanceof Error &&
      /^SENSOR_C2G_SECURITY_4663_RECEIPT_[A-Z0-9_]+$/.test(error.message)
      ? error.message
      : "SENSOR_C2G_SECURITY_4663_RECEIPT_CHECK_FAILED";
    process.stderr.write(`${code}\n`);
    process.exitCode = 1;
  });
}
