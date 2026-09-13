import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import { sha256, stableJson } from "../domain/stable-json.js";
import { AUDIT_HEAD_GENESIS_HASH } from "./audit-head-checkpoint-contract.js";
import {
  AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1,
  verifyAuditWitnessDatabaseHeadV1
} from "./audit-witness-database-head.js";

type SnapshotRow = {
  sequence: number;
  id: string;
  occurred_at: string;
  event_type: string;
  payload_json: string;
  previous_hash: string;
  event_hash: string;
};

function rows(count: number): SnapshotRow[] {
  const result: SnapshotRow[] = [];
  let previousHash = AUDIT_HEAD_GENESIS_HASH;
  for (let sequence = 1; sequence <= count; sequence += 1) {
    const occurredAt = new Date(
      Date.UTC(2026, 7, 22, 12, 0, sequence)
    ).toISOString();
    const eventType = `audit.acquire.${sequence}`;
    const payloadJson = stableJson({ sequence });
    const eventHash = sha256(
      `${previousHash}\n${occurredAt}\n${eventType}\n${payloadJson}`
    );
    result.push({
      sequence,
      id: randomUUID(),
      occurred_at: occurredAt,
      event_type: eventType,
      payload_json: payloadJson,
      previous_hash: previousHash,
      event_hash: eventHash
    });
    previousHash = eventHash;
  }
  return result;
}

function metadata(snapshot: SnapshotRow[]) {
  const last = snapshot.at(-1);
  return {
    schemaVersion: 1 as const,
    purpose: AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1,
    capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
    rowCount: snapshot.length,
    minimumSequence: snapshot.length === 0 ? 0 : 1,
    maximumSequence: last?.sequence ?? 0,
    headEventHash: last?.event_hash ?? AUDIT_HEAD_GENESIS_HASH
  };
}

describe("audit-witness existing database head acquisition", () => {
  it("derives a head only after verifying the complete genesis prefix", () => {
    const snapshot = rows(3);
    const result = verifyAuditWitnessDatabaseHeadV1({
      metadata: metadata(snapshot),
      rows: snapshot
    });
    assert.equal(result.claim, AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1);
    assert.equal(result.status, "ready");
    assert.equal(result.bootstrapAllowed, true);
    assert.equal(result.rowsVerified, 3);
    assert.equal(result.databaseHeadSequence, 3);
    assert.equal(result.databaseHeadEventHash, snapshot[2]!.event_hash);
    assert.match(result.verifiedPrefixSha256, /^[a-f0-9]{64}$/);
  });

  it("classifies an exactly empty snapshot but forbids bootstrap", () => {
    assert.deepEqual(
      verifyAuditWitnessDatabaseHeadV1({ metadata: metadata([]), rows: [] }),
      {
        schemaVersion: 1,
        claim: AUDIT_WITNESS_DATABASE_SNAPSHOT_CLAIM_V1,
        status: "empty",
        bootstrapAllowed: false,
        rowsVerified: 0,
        databaseHeadSequence: 0,
        databaseHeadEventHash: AUDIT_HEAD_GENESIS_HASH,
        verifiedPrefixSha256: sha256(stableJson([]))
      }
    );
  });

  it("rejects malformed, non-transactional and non-strict inputs", () => {
    const snapshot = rows(1);
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: { ...metadata(snapshot), purpose: "wrong" },
          rows: snapshot
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: { ...metadata(snapshot), capture: "head-row-only" },
          rows: snapshot
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: { ...metadata(snapshot), extra: true },
          rows: snapshot
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: "not-rows"
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: snapshot,
          extra: true
        } as Parameters<typeof verifyAuditWitnessDatabaseHeadV1>[0]),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_INPUT_INVALID/
    );
  });

  it("rejects row schema drift and oversized row counts", () => {
    const snapshot = rows(1);
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: [{ ...snapshot[0]!, extra: true }]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_ROW_INVALID/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: new Array(
            AUDIT_WITNESS_DATABASE_SNAPSHOT_MAXIMUM_ROWS + 1
          ).fill(snapshot[0])
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_TOO_LARGE/
    );
  });

  it("rejects count, range and claimed-head metadata drift", () => {
    const snapshot = rows(2);
    for (const changed of [
      { rowCount: 1 },
      { minimumSequence: 0 },
      { maximumSequence: 3 },
      { headEventHash: "f".repeat(64) }
    ]) {
      assert.throws(
        () =>
          verifyAuditWitnessDatabaseHeadV1({
            metadata: { ...metadata(snapshot), ...changed },
            rows: snapshot
          }),
        /AUDIT_WITNESS_DATABASE_ACQUISITION_METADATA_MISMATCH/
      );
    }
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: { ...metadata([]), rowCount: 1 },
          rows: []
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_METADATA_MISMATCH/
    );
  });

  it("rejects sequence gaps, prior-hash drift and event-hash drift", () => {
    const snapshot = rows(3);
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: [snapshot[0], { ...snapshot[1]!, sequence: 3 }, snapshot[2]]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_SEQUENCE_INVALID/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: [
            { ...snapshot[0]!, previous_hash: "f".repeat(64) },
            snapshot[1],
            snapshot[2]
          ]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_CHAIN_BROKEN/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: [
            snapshot[0],
            { ...snapshot[1]!, previous_hash: "f".repeat(64) },
            snapshot[2]
          ]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_CHAIN_BROKEN/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: [
            snapshot[0],
            snapshot[1],
            { ...snapshot[2]!, event_hash: "f".repeat(64) }
          ]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_METADATA_MISMATCH/
    );
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: {
            ...metadata(snapshot),
            headEventHash: "f".repeat(64)
          },
          rows: [
            snapshot[0],
            snapshot[1],
            { ...snapshot[2]!, event_hash: "f".repeat(64) }
          ]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_HASH_INVALID/
    );
  });

  it("rejects duplicate database identities even when hashes remain valid", () => {
    const snapshot = rows(2);
    assert.throws(
      () =>
        verifyAuditWitnessDatabaseHeadV1({
          metadata: metadata(snapshot),
          rows: [snapshot[0], { ...snapshot[1]!, id: snapshot[0]!.id }]
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_DUPLICATE_INVALID/
    );
  });
});
