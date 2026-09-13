import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { describe, it } from "node:test";
import { stableJson } from "../domain/stable-json.js";
import {
  AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
  AUDIT_HEAD_GENESIS_HASH,
  AUDIT_HEAD_SIGNER_ALGORITHM_V1,
  AUDIT_HEAD_SIGNER_PROFILE_V1,
  advanceAuditHeadCheckpointStateV1,
  auditHeadCheckpointHashV1,
  type AuditHeadCheckpointCoreV1,
  type AuditHeadCheckpointStateV1,
  type SignedAuditHeadCheckpointV1
} from "./audit-head-checkpoint-contract.js";

const chainId = "c".repeat(64);
const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const spki = keys.publicKey.export({ format: "der", type: "spki" });
const signerFingerprint = createHash("sha256").update(spki).digest("hex");

function signedCheckpoint(input: {
  sequence: number;
  eventHash: string;
  priorSequence?: number;
  priorEventHash?: string;
  priorCheckpointHash?: string;
}): SignedAuditHeadCheckpointV1 {
  const core: AuditHeadCheckpointCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
    chainId,
    priorSequence: input.priorSequence ?? 0,
    priorEventHash: input.priorEventHash ?? AUDIT_HEAD_GENESIS_HASH,
    priorCheckpointHash:
      input.priorCheckpointHash ?? AUDIT_HEAD_GENESIS_HASH,
    sequence: input.sequence,
    eventHash: input.eventHash,
    signerProfile: AUDIT_HEAD_SIGNER_PROFILE_V1,
    signerAlgorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
    signerPublicKeyFingerprintSha256: signerFingerprint
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

const verifySignature = (
  payload: string,
  signatureBase64: string,
  fingerprint: string
) =>
  fingerprint === signerFingerprint &&
  verify(
    "sha256",
    Buffer.from(payload, "utf8"),
    { key: keys.publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(signatureBase64, "base64")
  );

function advance(
  candidate: unknown,
  currentState: AuditHeadCheckpointStateV1 | null,
  observation: unknown
) {
  return advanceAuditHeadCheckpointStateV1({
    candidate,
    currentState,
    observation,
    expectedChainId: chainId,
    expectedSignerPublicKeyFingerprintSha256: signerFingerprint,
    verifySignature
  });
}

describe("audit-head-checkpoint-v1 contract", () => {
  it("matches the exact native and TypeScript canonical checkpoint vector", () => {
    const vector: AuditHeadCheckpointCoreV1 = {
      schemaVersion: 1,
      purpose: AUDIT_HEAD_CHECKPOINT_PURPOSE_V1,
      chainId: "a".repeat(64),
      priorSequence: 0,
      priorEventHash: AUDIT_HEAD_GENESIS_HASH,
      priorCheckpointHash: AUDIT_HEAD_GENESIS_HASH,
      sequence: 2,
      eventHash: "c".repeat(64),
      signerProfile: AUDIT_HEAD_SIGNER_PROFILE_V1,
      signerAlgorithm: AUDIT_HEAD_SIGNER_ALGORITHM_V1,
      signerPublicKeyFingerprintSha256: "f".repeat(64)
    };
    assert.equal(
      auditHeadCheckpointHashV1(vector),
      "08c170dd7f52550d6acc9a14f8351369f642c5dfec15d8d4f4933402ce334a72"
    );
  });

  it("accepts a domain-separated first checkpoint and a continuous later checkpoint", () => {
    const first = signedCheckpoint({ sequence: 2, eventHash: "a".repeat(64) });
    let signedPayload = "";
    const firstState = advanceAuditHeadCheckpointStateV1({
      candidate: first,
      currentState: null,
      observation: {
        databaseHeadSequence: 2,
        checkpointEventHashAtSequence: "a".repeat(64),
        priorCheckpointEventHashAtSequence: null
      },
      expectedChainId: chainId,
      expectedSignerPublicKeyFingerprintSha256: signerFingerprint,
      verifySignature: (payload, signature, fingerprint) => {
        signedPayload = payload;
        return verifySignature(payload, signature, fingerprint);
      }
    });
    assert.match(signedPayload, /project15\.audit-head-checkpoint\.v1/);

    const second = signedCheckpoint({
      priorSequence: firstState.sequence,
      priorEventHash: firstState.eventHash,
      priorCheckpointHash: firstState.checkpointHash,
      sequence: 5,
      eventHash: "b".repeat(64)
    });
    const secondState = advance(second, firstState, {
      databaseHeadSequence: 7,
      checkpointEventHashAtSequence: "b".repeat(64),
      priorCheckpointEventHashAtSequence: "a".repeat(64)
    });
    assert.deepEqual(secondState, {
      chainId,
      sequence: 5,
      eventHash: "b".repeat(64),
      checkpointHash: second.checkpointHash
    });
  });

  it("rejects schema, domain, hash, signer and signature drift", () => {
    const checkpoint = signedCheckpoint({ sequence: 1, eventHash: "a".repeat(64) });
    const observation = {
      databaseHeadSequence: 1,
      checkpointEventHashAtSequence: "a".repeat(64),
      priorCheckpointEventHashAtSequence: null
    };
    assert.throws(
      () => advance({ ...checkpoint, command: "forbidden" }, null, observation),
      /AUDIT_HEAD_CHECKPOINT_SCHEMA_INVALID/
    );
    assert.throws(
      () => advance({ ...checkpoint, purpose: "audit-head-v1" }, null, observation),
      /AUDIT_HEAD_CHECKPOINT_SCHEMA_INVALID/
    );
    assert.throws(
      () =>
        advance(
          { ...checkpoint, sequence: Number.MAX_SAFE_INTEGER + 1 },
          null,
          observation
        ),
      /AUDIT_HEAD_CHECKPOINT_SCHEMA_INVALID/
    );
    assert.throws(
      () =>
        advance(
          { ...checkpoint, signatureBase64: checkpoint.signatureBase64.replace(/=+$/, "") },
          null,
          observation
        ),
      /AUDIT_HEAD_CHECKPOINT_SCHEMA_INVALID/
    );
    assert.throws(
      () => advance({ ...checkpoint, checkpointHash: "f".repeat(64) }, null, observation),
      /AUDIT_HEAD_CHECKPOINT_HASH_INVALID/
    );
    assert.throws(
      () =>
        advanceAuditHeadCheckpointStateV1({
          candidate: checkpoint,
          currentState: null,
          observation,
          expectedChainId: "d".repeat(64),
          expectedSignerPublicKeyFingerprintSha256: signerFingerprint,
          verifySignature
        }),
      /AUDIT_HEAD_CHECKPOINT_CHAIN_MISMATCH/
    );
    assert.throws(
      () =>
        advanceAuditHeadCheckpointStateV1({
          candidate: checkpoint,
          currentState: null,
          observation,
          expectedChainId: chainId,
          expectedSignerPublicKeyFingerprintSha256: "e".repeat(64),
          verifySignature
        }),
      /AUDIT_HEAD_CHECKPOINT_SIGNER_MISMATCH/
    );
    const badSignature = Buffer.from(checkpoint.signatureBase64, "base64");
    badSignature[0] = badSignature[0]! ^ 1;
    assert.throws(
      () =>
        advance(
          { ...checkpoint, signatureBase64: badSignature.toString("base64") },
          null,
          observation
        ),
      /AUDIT_HEAD_CHECKPOINT_SIGNATURE_INVALID/
    );
  });

  it("rejects rollback and broken checkpoint continuity", () => {
    const first = signedCheckpoint({ sequence: 2, eventHash: "a".repeat(64) });
    const state = advance(first, null, {
      databaseHeadSequence: 2,
      checkpointEventHashAtSequence: "a".repeat(64),
      priorCheckpointEventHashAtSequence: null
    });
    const rollback = signedCheckpoint({
      priorSequence: state.sequence,
      priorEventHash: state.eventHash,
      priorCheckpointHash: state.checkpointHash,
      sequence: 2,
      eventHash: "b".repeat(64)
    });
    assert.throws(
      () =>
        advance(rollback, state, {
          databaseHeadSequence: 2,
          checkpointEventHashAtSequence: "b".repeat(64),
          priorCheckpointEventHashAtSequence: "a".repeat(64)
        }),
      /AUDIT_HEAD_CHECKPOINT_ROLLBACK/
    );

    const disconnected = signedCheckpoint({
      priorSequence: 2,
      priorEventHash: "a".repeat(64),
      priorCheckpointHash: "d".repeat(64),
      sequence: 3,
      eventHash: "b".repeat(64)
    });
    assert.throws(
      () =>
        advance(disconnected, state, {
          databaseHeadSequence: 3,
          checkpointEventHashAtSequence: "b".repeat(64),
          priorCheckpointEventHashAtSequence: "a".repeat(64)
        }),
      /AUDIT_HEAD_CHECKPOINT_CONTINUITY_INVALID/
    );
  });

  it("rejects a validly signed recomputed chain and an unanchored database prefix", () => {
    const first = signedCheckpoint({ sequence: 2, eventHash: "a".repeat(64) });
    const state = advance(first, null, {
      databaseHeadSequence: 2,
      checkpointEventHashAtSequence: "a".repeat(64),
      priorCheckpointEventHashAtSequence: null
    });
    const recomputed = signedCheckpoint({
      priorSequence: state.sequence,
      priorEventHash: state.eventHash,
      priorCheckpointHash: state.checkpointHash,
      sequence: 5,
      eventHash: "b".repeat(64)
    });
    assert.throws(
      () =>
        advance(recomputed, state, {
          databaseHeadSequence: 5,
          checkpointEventHashAtSequence: "b".repeat(64),
          priorCheckpointEventHashAtSequence: "e".repeat(64)
        }),
      /AUDIT_HEAD_CHECKPOINT_CHAIN_RECOMPUTED/
    );
    assert.throws(
      () =>
        advance(recomputed, state, {
          databaseHeadSequence: 4,
          checkpointEventHashAtSequence: null,
          priorCheckpointEventHashAtSequence: "a".repeat(64)
        }),
      /AUDIT_HEAD_CHECKPOINT_PREFIX_INVALID/
    );
  });
});
