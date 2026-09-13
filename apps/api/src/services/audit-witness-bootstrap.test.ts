import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";
import { randomUUID } from "node:crypto";
import { sha256, stableJson } from "../domain/stable-json.js";
import {
  AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
  AUDIT_HEAD_GENESIS_HASH,
  AUDIT_HEAD_KEY_PERSISTENCE_V1,
  AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1,
  AUDIT_HEAD_SIGNER_ALGORITHM_V1,
  AUDIT_HEAD_SIGNER_PROFILE_V1,
  auditHeadCheckpointHashV1,
  type AuditHeadCheckpointCoreV1,
  type AuditHeadProtectedDocumentV1
} from "./audit-head-checkpoint-contract.js";
import {
  auditWitnessBootstrapAnchorHashV1,
  createAuditWitnessPrepareV1,
  parseAuditWitnessBytesV1,
  serializeAuditWitnessRecordV1
} from "./audit-witness-contract.js";
import { createTrustedAuditWitnessBootstrapV1 } from "./audit-witness-bootstrap.js";
import {
  AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
  AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1
} from "./audit-witness-database-head.js";

const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = keys.publicKey.export({ format: "der", type: "spki" });
const fingerprint = createHash("sha256").update(spki).digest("hex");
const chainId = sha256(`project15.audit-head-chain.v1\n${fingerprint}`);
function databaseSnapshot(count = 3) {
  const rows = [];
  let previousHash = AUDIT_HEAD_GENESIS_HASH;
  for (let sequence = 1; sequence <= count; sequence += 1) {
    const occurredAt = new Date(
      Date.UTC(2026, 7, 22, 12, 0, sequence)
    ).toISOString();
    const eventType = `audit.bootstrap.${sequence}`;
    const payloadJson = stableJson({ sequence });
    const eventHash = sha256(
      `${previousHash}\n${occurredAt}\n${eventType}\n${payloadJson}`
    );
    rows.push({
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
  return {
    metadata: {
      schemaVersion: 1,
      purpose: AUDIT_WITNESS_DATABASE_SNAPSHOT_PURPOSE_V1,
      capture: AUDIT_WITNESS_DATABASE_SNAPSHOT_CAPTURE_V1,
      rowCount: rows.length,
      minimumSequence: rows.length === 0 ? 0 : 1,
      maximumSequence: rows.length,
      headEventHash: rows.at(-1)?.event_hash ?? AUDIT_HEAD_GENESIS_HASH
    },
    rows
  };
}

function protectedDocument(
  sequence: number,
  eventHash: string
): AuditHeadProtectedDocumentV1 {
  const core: AuditHeadCheckpointCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
    chainId,
    priorSequence: 0,
    priorEventHash: AUDIT_HEAD_GENESIS_HASH,
    priorCheckpointHash: AUDIT_HEAD_GENESIS_HASH,
    sequence,
    eventHash,
    signerProfile: AUDIT_HEAD_SIGNER_PROFILE_V1,
    signerAlgorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
    signerPublicKeyFingerprintSha256: fingerprint
  };
  const signatureBase64 = sign(
    "sha256",
    Buffer.from(stableJson(core), "utf8"),
    { key: keys.privateKey, dsaEncoding: "ieee-p1363" }
  ).toString("base64");
  return {
    signer: {
      profile: AUDIT_HEAD_SIGNER_PROFILE_V1,
      chainId,
      algorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
      publicKeyFormat: AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1,
      publicKeySpkiBase64: spki.toString("base64"),
      publicKeyFingerprintSha256: fingerprint,
      keyPersistence: AUDIT_HEAD_KEY_PERSISTENCE_V1
    },
    checkpoint: {
      ...core,
      checkpointHash: auditHeadCheckpointHashV1(core),
      signatureBase64
    }
  };
}

describe("trusted audit-witness checkpoint bootstrap", () => {
  it("binds the initial witness state to the independently pinned checkpoint", () => {
    const snapshot = databaseSnapshot();
    const eventHash = snapshot.rows.at(-1)!.event_hash;
    const document = protectedDocument(snapshot.rows.length, eventHash);
    const state = createTrustedAuditWitnessBootstrapV1({
      protectedDocument: document,
      expectedSignerPublicKeyFingerprintSha256: fingerprint,
      databaseSnapshot: snapshot
    });
    assert.equal(state.chainId, chainId);
    assert.equal(state.committedSequence, 3);
    assert.equal(state.bootstrapCheckpointHash, document.checkpoint.checkpointHash);
    assert.equal(
      state.lastRecordHash,
      auditWitnessBootstrapAnchorHashV1({
        schemaVersion: 1,
        purpose: "project15.audit-witness-bootstrap.v1",
        chainId,
        sequence: 3,
        eventHash,
        checkpointHash: document.checkpoint.checkpointHash,
        signerPublicKeyFingerprintSha256: fingerprint
      })
    );
    assert.equal(state.recordCount, 0);

    const prepare = createAuditWitnessPrepareV1({
      currentState: state,
      eventHash: "b".repeat(64),
      occurredAtUtc: "2026-08-22T13:00:00.000Z"
    });
    assert.equal(prepare.sequence, 4);
    assert.equal(prepare.previousRecordHash, state.lastRecordHash);
    assert.equal(prepare.previousEventHash, eventHash);
    const parsed = parseAuditWitnessBytesV1({
      bytes: serializeAuditWitnessRecordV1(prepare),
      initialState: state
    });
    assert.equal(parsed.state.pendingPrepare?.sequence, 4);
  });

  it("rejects signer pin, checkpoint signature and database-head drift", () => {
    const snapshot = databaseSnapshot();
    const eventHash = snapshot.rows.at(-1)!.event_hash;
    const document = protectedDocument(snapshot.rows.length, eventHash);
    assert.throws(
      () =>
        createTrustedAuditWitnessBootstrapV1({
          protectedDocument: document,
          expectedSignerPublicKeyFingerprintSha256: "f".repeat(64),
          databaseSnapshot: snapshot
        }),
      /AUDIT_HEAD_PROTECTED_SIGNER_MISMATCH/
    );
    assert.throws(
      () =>
        createTrustedAuditWitnessBootstrapV1({
          protectedDocument: {
            ...document,
            checkpoint: {
              ...document.checkpoint,
              eventHash: "b".repeat(64)
            }
          },
          expectedSignerPublicKeyFingerprintSha256: fingerprint,
          databaseSnapshot: snapshot
        }),
      /AUDIT_HEAD_PROTECTED_SIGNATURE_INVALID/
    );
    assert.throws(
      () =>
        createTrustedAuditWitnessBootstrapV1({
          protectedDocument: document,
          expectedSignerPublicKeyFingerprintSha256: fingerprint,
          databaseSnapshot: {
            ...snapshot,
            metadata: {
              ...snapshot.metadata,
              headEventHash: "b".repeat(64)
            },
            rows: [
              ...snapshot.rows.slice(0, -1),
              {
                ...snapshot.rows.at(-1)!,
                event_hash: "b".repeat(64)
              }
            ]
          }
        }),
      /AUDIT_WITNESS_DATABASE_ACQUISITION_HASH_INVALID/
    );
    const longerSnapshot = databaseSnapshot(4);
    assert.throws(
      () =>
        createTrustedAuditWitnessBootstrapV1({
          protectedDocument: document,
          expectedSignerPublicKeyFingerprintSha256: fingerprint,
          databaseSnapshot: longerSnapshot
        }),
      /AUDIT_WITNESS_BOOTSTRAP_DATABASE_MISMATCH/
    );
    const intermediateDocument = protectedDocument(
      2,
      snapshot.rows[1]!.event_hash
    );
    assert.throws(
      () =>
        createTrustedAuditWitnessBootstrapV1({
          protectedDocument: intermediateDocument,
          expectedSignerPublicKeyFingerprintSha256: fingerprint,
          databaseSnapshot: snapshot
        }),
      /AUDIT_WITNESS_BOOTSTRAP_DATABASE_MISMATCH/
    );
    assert.throws(
      () =>
        createTrustedAuditWitnessBootstrapV1({
          protectedDocument: document,
          expectedSignerPublicKeyFingerprintSha256: fingerprint,
          databaseSnapshot: databaseSnapshot(0)
        }),
      /AUDIT_WITNESS_BOOTSTRAP_DATABASE_MISMATCH/
    );
  });
});
