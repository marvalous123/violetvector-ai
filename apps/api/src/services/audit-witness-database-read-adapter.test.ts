import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import { sha256, stableJson } from "../domain/stable-json.js";
import { AUDIT_HEAD_GENESIS_HASH } from "./audit-head-checkpoint-contract.js";
import {
  AUDIT_WITNESS_DATABASE_READ_PURPOSE_V1,
  AUDIT_WITNESS_DATABASE_READ_REQUEST_V1,
  acquireAuditWitnessDatabaseHeadV1,
  type AuditWitnessDatabaseReadRequestV1
} from "./audit-witness-database-read-adapter.js";
import {
  AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1
} from "./audit-witness-database-head.js";

function snapshot() {
  const occurredAt = "2026-08-22T19:30:00.000Z";
  const eventType = "audit.adapter.test";
  const payloadJson = stableJson({ source: "fixed-fixture" });
  const eventHash = sha256(
    `${AUDIT_HEAD_GENESIS_HASH}\n${occurredAt}\n${eventType}\n${payloadJson}`
  );
  return {
    metadata: {
      schemaVersion: 1,
      purpose: AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1,
      capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
      rowCount: 1,
      minimumSequence: 1,
      maximumSequence: 1,
      headEventHash: eventHash
    },
    rows: [
      {
        sequence: 1,
        id: randomUUID(),
        occurred_at: occurredAt,
        event_type: eventType,
        payload_json: payloadJson,
        previous_hash: AUDIT_HEAD_GENESIS_HASH,
        event_hash: eventHash
      }
    ]
  };
}

describe("disabled audit-witness database read adapter boundary", () => {
  it("issues one immutable fixed read request and verifies its response", () => {
    const seen: AuditWitnessDatabaseReadRequestV1[] = [];
    const result = acquireAuditWitnessDatabaseHeadV1({
      readCompletePrefixSnapshot(request) {
        seen.push(request);
        return snapshot();
      }
    });
    assert.equal(seen.length, 1);
    assert.equal(seen[0], AUDIT_WITNESS_DATABASE_READ_REQUEST_V1);
    assert.deepEqual(seen[0], {
      schemaVersion: 1,
      purpose: AUDIT_WITNESS_DATABASE_READ_PURPOSE_V1,
      capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
      table: "audit_events",
      columns: [
        "sequence",
        "id",
        "occurred_at",
        "event_type",
        "payload_json",
        "previous_hash",
        "event_hash"
      ],
      orderBy: { column: "sequence", direction: "ASC" },
      maximumRows: 4096,
      readOnly: true,
      runtimeWiringEnabled: false
    });
    assert.equal(Object.isFrozen(seen[0]), true);
    assert.equal(Object.isFrozen(seen[0]!.columns), true);
    assert.equal(Object.isFrozen(seen[0]!.orderBy), true);
    assert.equal(result.status, "ready");
    assert.equal(result.rowsVerified, 1);
  });

  it("maps one reader failure without retrying", () => {
    let calls = 0;
    assert.throws(
      () =>
        acquireAuditWitnessDatabaseHeadV1({
          readCompletePrefixSnapshot() {
            calls += 1;
            throw new Error("fixture failure");
          }
        }),
      /AUDIT_WITNESS_DATABASE_READ_FAILED/
    );
    assert.equal(calls, 1);
  });

  it("rejects asynchronous, malformed and authority-expanded responses", () => {
    for (const response of [
      Promise.resolve(snapshot()),
      null,
      { metadata: snapshot().metadata },
      { ...snapshot(), command: "continue" }
    ]) {
      assert.throws(
        () =>
          acquireAuditWitnessDatabaseHeadV1({
            readCompletePrefixSnapshot() {
              return response;
            }
          }),
        /AUDIT_WITNESS_DATABASE_READ_RESPONSE_INVALID/
      );
    }
  });

  it("propagates complete-prefix verification failures", () => {
    const invalid = snapshot();
    invalid.rows[0]!.previous_hash = "f".repeat(64);
    assert.throws(
      () =>
        acquireAuditWitnessDatabaseHeadV1({
          readCompletePrefixSnapshot() {
            return invalid;
          }
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_CHAIN_BROKEN/
    );
  });

  it("returns an empty non-bootstrap observation without inventing history", () => {
    const result = acquireAuditWitnessDatabaseHeadV1({
      readCompletePrefixSnapshot() {
        return {
          metadata: {
            schemaVersion: 1,
            purpose: AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1,
            capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
            rowCount: 0,
            minimumSequence: 0,
            maximumSequence: 0,
            headEventHash: AUDIT_HEAD_GENESIS_HASH
          },
          rows: []
        };
      }
    });
    assert.equal(result.status, "empty");
    assert.equal(result.bootstrapAllowed, false);
    assert.equal(result.rowsVerified, 0);
  });
});
