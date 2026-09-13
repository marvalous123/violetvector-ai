import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import { sha256, stableJson } from "../domain/stable-json.js";
import {
  AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
  AUDIT_HEAD_GENESIS_HASH,
  AUDIT_HEAD_SIGNER_ALGORITHM_V1,
  AUDIT_HEAD_SIGNER_PROFILE_V1,
  AUDIT_HEAD_KEY_PERSISTENCE_V1,
  AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1,
  auditHeadCheckpointHashV1,
  type AuditHeadCheckpointCoreV1,
  type AuditHeadCheckpointStateV1,
  type SignedAuditHeadCheckpointV1
} from "./audit-head-checkpoint-contract.js";
import {
  AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS,
  prepareAuditHeadCheckpointProofV1,
  verifyAuditHeadProtectedDocumentV1,
  verifyProtectedAuditHeadReceiptV1,
  type AuditRowSnapshotV1
} from "./audit-head-checkpoint-proof.js";

const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = keys.publicKey.export({ format: "der", type: "spki" });
const fingerprint = createHash("sha256").update(spki).digest("hex");
const chainId = sha256(`project15.audit-head-chain.v1\n${fingerprint}`);

function rows(count: number, start: AuditRowSnapshotV1[] = []): AuditRowSnapshotV1[] {
  const result = [...start];
  let previousHash = result.at(-1)?.event_hash ?? AUDIT_HEAD_GENESIS_HASH;
  let sequence = (result.at(-1)?.sequence ?? 0) + 1;
  while (result.length < count) {
    const occurredAt = new Date(Date.UTC(2026, 7, 22, 12, 0, sequence)).toISOString();
    const eventType = `audit.test.${sequence}`;
    const payloadJson = stableJson({ sequence });
    const eventHash = sha256(`${previousHash}\n${occurredAt}\n${eventType}\n${payloadJson}`);
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
    sequence += 1;
  }
  return result;
}

function receipt(
  proof: ReturnType<typeof prepareAuditHeadCheckpointProofV1>
): SignedAuditHeadCheckpointV1 {
  const head = proof.rows.at(-1)!;
  const core: AuditHeadCheckpointCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
    chainId,
    priorSequence: proof.priorSequence,
    priorEventHash: proof.priorEventHash,
    priorCheckpointHash: proof.priorCheckpointHash,
    sequence: head.sequence,
    eventHash: head.eventHash,
    signerProfile: AUDIT_HEAD_SIGNER_PROFILE_V1,
    signerAlgorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
    signerPublicKeyFingerprintSha256: fingerprint
  };
  const payload = stableJson(core);
  return {
    ...core,
    checkpointHash: auditHeadCheckpointHashV1(core),
    signatureBase64: sign("sha256", Buffer.from(payload, "utf8"), {
      key: keys.privateKey,
      dsaEncoding: "ieee-p1363"
    }).toString("base64")
  };
}

const verifySignature = (payload: string, signature: string, candidateFingerprint: string) =>
  candidateFingerprint === fingerprint &&
  verify(
    "sha256",
    Buffer.from(payload, "utf8"),
    { key: keys.publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(signature, "base64")
  );

function verifyReceipt(
  signed: SignedAuditHeadCheckpointV1,
  currentState: AuditHeadCheckpointStateV1 | null,
  snapshot: AuditRowSnapshotV1[]
) {
  const head = snapshot.at(-1)!;
  return verifyProtectedAuditHeadReceiptV1({
    receipt: signed,
    currentState,
    rows: snapshot,
    databaseHead: { sequence: head.sequence, eventHash: head.event_hash },
    expectedChainId: chainId,
    expectedSignerPublicKeyFingerprintSha256: fingerprint,
    verifySignature
  });
}

describe("audit head checkpoint row proof", () => {
  it("verifies the strict native protected document and rejects signer drift", () => {
    const snapshot = rows(1);
    const signed = receipt(
      prepareAuditHeadCheckpointProofV1({ rows: snapshot, currentState: null })
    );
    const document = {
      signer: {
        profile: AUDIT_HEAD_SIGNER_PROFILE_V1,
        chainId,
        algorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
        publicKeyFormat: AUDIT_HEAD_PUBLIC_KEY_FORMAT_V1,
        publicKeySpkiBase64: spki.toString("base64"),
        publicKeyFingerprintSha256: fingerprint,
        keyPersistence: AUDIT_HEAD_KEY_PERSISTENCE_V1
      },
      checkpoint: signed
    };
    assert.deepEqual(verifyAuditHeadProtectedDocumentV1({
      document,
      expectedSignerPublicKeyFingerprintSha256: fingerprint
    }), document);
    assert.throws(
      () => verifyAuditHeadProtectedDocumentV1({
        document: {
          ...document,
          signer: { ...document.signer, chainId: "b".repeat(64) }
        },
        expectedSignerPublicKeyFingerprintSha256: fingerprint
      }),
      /AUDIT_HEAD_PROTECTED_SIGNER_MISMATCH/
    );
    assert.throws(
      () => verifyAuditHeadProtectedDocumentV1({
        document,
        expectedSignerPublicKeyFingerprintSha256: "b".repeat(64)
      }),
      /AUDIT_HEAD_PROTECTED_SIGNER_MISMATCH/
    );
  });

  it("prepares a bounded contiguous proof and verifies a checkpointed head", () => {
    const snapshot = rows(3);
    const proof = prepareAuditHeadCheckpointProofV1({ rows: snapshot, currentState: null });
    assert.equal(proof.rows.length, 3);
    assert.equal(proof.rows[0]!.previousHash, AUDIT_HEAD_GENESIS_HASH);
    const result = verifyReceipt(receipt(proof), null, snapshot);
    assert.deepEqual(result.tail, { status: "checkpointed", count: 0 });
    assert.equal(result.state.sequence, 3);
  });

  it("classifies valid rows after the signed receipt as an uncheckpointed tail", () => {
    const snapshot = rows(5);
    const proof = prepareAuditHeadCheckpointProofV1({ rows: snapshot.slice(0, 3), currentState: null });
    const result = verifyReceipt(receipt(proof), null, snapshot);
    assert.deepEqual(result.tail, {
      status: "uncheckpointed",
      count: 2,
      sequenceStart: 4,
      sequenceEnd: 5,
      headEventHash: snapshot[4]!.event_hash
    });
  });

  it("rejects malformed, oversized and noncontiguous preparation snapshots", () => {
    assert.throws(
      () => prepareAuditHeadCheckpointProofV1({ rows: [{ sequence: 1 }], currentState: null }),
      /AUDIT_HEAD_PROOF_SCHEMA_INVALID/
    );
    assert.throws(
      () => prepareAuditHeadCheckpointProofV1({ rows: rows(AUDIT_HEAD_MAXIMUM_CHECKPOINT_LINKS + 1), currentState: null }),
      /AUDIT_HEAD_PROOF_TOO_LARGE/
    );
    const gap = rows(2);
    gap[1] = { ...gap[1]!, sequence: 3 };
    assert.throws(
      () => prepareAuditHeadCheckpointProofV1({ rows: gap, currentState: null }),
      /AUDIT_HEAD_PROOF_CONTINUITY_INVALID/
    );
  });

  it("rejects recomputed-chain drift at the protected prior checkpoint", () => {
    const initialRows = rows(2);
    const firstProof = prepareAuditHeadCheckpointProofV1({ rows: initialRows, currentState: null });
    const first = verifyReceipt(receipt(firstProof), null, initialRows).state;
    const laterRows = rows(4);
    const nextProof = prepareAuditHeadCheckpointProofV1({ rows: laterRows.slice(2), currentState: first });
    const signed = receipt(nextProof);
    const anchoredSnapshot = laterRows.slice(1);
    let previousHash = anchoredSnapshot[0]!.previous_hash;
    for (let index = 0; index < anchoredSnapshot.length; index += 1) {
      const row = anchoredSnapshot[index]!;
      const payloadJson =
        index === 0 ? stableJson({ recomputed: true }) : row.payload_json;
      const eventHash = sha256(
        `${previousHash}\n${row.occurred_at}\n${row.event_type}\n${payloadJson}`
      );
      anchoredSnapshot[index] = {
        ...row,
        payload_json: payloadJson,
        previous_hash: previousHash,
        event_hash: eventHash
      };
      previousHash = eventHash;
    }
    assert.throws(
      () => verifyReceipt(signed, first, anchoredSnapshot),
      /AUDIT_HEAD_CHECKPOINT_CHAIN_RECOMPUTED/
    );
  });

  it("rejects truncated snapshots and receipt rollback", () => {
    const initialRows = rows(2);
    const firstProof = prepareAuditHeadCheckpointProofV1({ rows: initialRows, currentState: null });
    const signedFirst = receipt(firstProof);
    const first = verifyReceipt(signedFirst, null, initialRows).state;
    assert.throws(
      () =>
        verifyProtectedAuditHeadReceiptV1({
          receipt: signedFirst,
          currentState: null,
          rows: initialRows.slice(0, 1),
          databaseHead: { sequence: 2, eventHash: initialRows[1]!.event_hash },
          expectedChainId: chainId,
          expectedSignerPublicKeyFingerprintSha256: fingerprint,
          verifySignature
        }),
      /AUDIT_HEAD_DATABASE_SNAPSHOT_TRUNCATED/
    );
    assert.throws(
      () => verifyReceipt(signedFirst, first, initialRows.slice(1)),
      /AUDIT_HEAD_CHECKPOINT_ROLLBACK/
    );
  });
});
