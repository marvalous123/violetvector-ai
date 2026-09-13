import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BLUE_RULES } from "./blue-detection-service.js";
import {
  assessEndpointCoverage,
  telemetryBatchHash,
  telemetryReceiptSchema,
  validateSignedTelemetryBatch
} from "./endpoint-telemetry-contract.js";

const connectorId = "connector-lab-12345678";
const endpointId = "endpoint-lab-12345678";
const fingerprint = "a".repeat(64);
const sourceRecordIdHash = "b".repeat(64);

function validCore() {
  return {
    schemaVersion: 1 as const,
    missionId: "mission-blue",
    connectorId,
    endpointId,
    certificateFingerprintSha256: fingerprint,
    sequenceStart: 41,
    sequenceEnd: 42,
    previousBatchHash: "c".repeat(64),
    events: [
      {
        mode: "live" as const,
        schemaVersion: 1 as const,
        eventId: "event-lab-00000041",
        occurredAt: "2026-07-19T12:00:00.000Z",
        connectorId,
        endpointId,
        bootId: "boot-lab-12345678",
        sequence: 41,
        telemetryClass: "endpoint" as const,
        signal: "password-store-read" as const,
        actorTrust: "untrusted" as const,
        sourceRecordIdHash,
        mappingVersion: "windows-blue-v1" as const,
        redaction: { applied: true as const, fieldsRemoved: 2, valuesHashed: 3 }
      },
      {
        mode: "live" as const,
        schemaVersion: 1 as const,
        eventId: "event-lab-00000042",
        occurredAt: "2026-07-19T12:00:01.000Z",
        connectorId,
        endpointId,
        bootId: "boot-lab-12345678",
        sequence: 42,
        telemetryClass: "endpoint" as const,
        signal: "security-tool-impairment" as const,
        actorTrust: "untrusted" as const,
        sourceRecordIdHash,
        mappingVersion: "windows-blue-v1" as const,
        redaction: { applied: true as const, fieldsRemoved: 1, valuesHashed: 2 }
      }
    ]
  };
}

describe("read-only endpoint telemetry contract", () => {
  it("accepts only a bound, contiguous, hash-verified and signed batch", () => {
    const core = validCore();
    const batch = {
      ...core,
      batchHash: telemetryBatchHash(core),
      signatureBase64: "A".repeat(64)
    };
    const parsed = validateSignedTelemetryBatch(
      batch,
      (payload, signature, certificate) =>
        payload.length > 0 && signature === batch.signatureBase64 && certificate === fingerprint
    );
    assert.equal(parsed.events.length, 2);
    assert.equal(parsed.sequenceEnd, 42);
  });

  it("rejects commands, raw paths, credential values, binding drift and sequence gaps", () => {
    const core = validCore();
    const unsafe = {
      ...core,
      events: [{ ...core.events[0]!, commandLine: "forbidden" }, core.events[1]!],
      batchHash: telemetryBatchHash(core),
      signatureBase64: "A".repeat(64)
    };
    assert.throws(() => validateSignedTelemetryBatch(unsafe, () => true));

    const reboundCore = {
      ...core,
      events: [core.events[0]!, { ...core.events[1]!, endpointId: "endpoint-other-12345678" }]
    };
    assert.throws(
      () =>
        validateSignedTelemetryBatch(
          { ...reboundCore, batchHash: telemetryBatchHash(reboundCore), signatureBase64: "A".repeat(64) },
          () => true
        ),
      /ENDPOINT_BINDING_MISMATCH/
    );

    const gapCore = {
      ...core,
      events: [core.events[0]!, { ...core.events[1]!, sequence: 44 }]
    };
    assert.throws(
      () =>
        validateSignedTelemetryBatch(
          { ...gapCore, batchHash: telemetryBatchHash(gapCore), signatureBase64: "A".repeat(64) },
          () => true
        ),
      /ENDPOINT_SEQUENCE_INVALID/
    );
  });

  it("keeps acknowledgements data-only with no action channel", () => {
    assert.deepEqual(
      telemetryReceiptSchema.parse({
        batchId: "batch-lab-12345678",
        acceptedSequence: 42,
        receiptHash: "d".repeat(64)
      }),
      {
        batchId: "batch-lab-12345678",
        acceptedSequence: 42,
        receiptHash: "d".repeat(64)
      }
    );
    assert.throws(() =>
      telemetryReceiptSchema.parse({
        batchId: "batch-lab-12345678",
        acceptedSequence: 42,
        receiptHash: "d".repeat(64),
        action: "run-command"
      })
    );
  });

  it("never marks stale or incomplete endpoint telemetry as live-supported", () => {
    const now = new Date("2026-07-19T12:00:00.000Z");
    const endpointOnly = assessEndpointCoverage(
      BLUE_RULES,
      {
        connectorId,
        endpointId,
        health: "healthy",
        lastEventAt: now.toISOString(),
        availableTelemetryClasses: ["endpoint"]
      },
      now
    );
    assert.equal(endpointOnly.find((item) => item.ruleId === "BR-PAYLOAD-001")?.readiness, "live-supported");
    assert.equal(endpointOnly.find((item) => item.ruleId === "BR-CRED-005")?.readiness, "synthetic-validated");

    const stale = assessEndpointCoverage(
      BLUE_RULES,
      {
        connectorId,
        endpointId,
        health: "healthy",
        lastEventAt: "2026-07-19T11:00:00.000Z",
        availableTelemetryClasses: ["endpoint", "identity", "cloud", "certificate-authority"]
      },
      now
    );
    assert.equal(stale.every((item) => item.readiness === "synthetic-validated"), true);
    assert.equal(stale.every((item) => item.health === "stale"), true);
  });
});
