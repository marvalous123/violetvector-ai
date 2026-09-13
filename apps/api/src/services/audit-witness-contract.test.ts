import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  AUDIT_WITNESS_GENESIS_HASH,
  AUDIT_WITNESS_CLAIM_V1,
  AUDIT_WITNESS_RECORD_PURPOSE_V1,
  advanceAuditWitnessStateV1,
  auditWitnessRecordHashV1,
  createAuditWitnessAbortV1,
  createAuditWitnessCommitV1,
  createAuditWitnessGenesisStateV1,
  createAuditWitnessPrepareV1,
  parseAuditWitnessBytesV1,
  reconcileAuditWitnessV1,
  serializeAuditWitnessRecordV1,
  type AuditWitnessRecordCoreV1,
  type AuditWitnessRecordV1
} from "./audit-witness-contract.js";

const chainId = "a".repeat(64);
const firstEventHash = "b".repeat(64);

function prepared() {
  const genesis = createAuditWitnessGenesisStateV1(chainId);
  const prepare = createAuditWitnessPrepareV1({
    currentState: genesis,
    eventHash: firstEventHash,
    occurredAtUtc: "2026-08-22T12:00:01.000Z"
  });
  const state = advanceAuditWitnessStateV1({
    currentState: genesis,
    record: prepare
  });
  return { genesis, prepare, state };
}

function coreOf(record: AuditWitnessRecordV1): AuditWitnessRecordCoreV1 {
  return {
    schemaVersion: record.schemaVersion,
    purpose: record.purpose,
    phase: record.phase,
    chainId: record.chainId,
    sequence: record.sequence,
    previousRecordHash: record.previousRecordHash,
    previousEventHash: record.previousEventHash,
    eventHash: record.eventHash,
    occurredAtUtc: record.occurredAtUtc,
    prepareRecordHash: record.prepareRecordHash
  };
}

describe("audit-witness-v1 pure crash contract", () => {
  it("matches the native canonical PREPARE and COMMIT vectors", () => {
    assert.equal(AUDIT_WITNESS_CLAIM_V1, "historical-rewrite-detection-only");
    const prepareCore: AuditWitnessRecordCoreV1 = {
      schemaVersion: 1,
      purpose: AUDIT_WITNESS_RECORD_PURPOSE_V1,
      phase: "PREPARE",
      chainId,
      sequence: 1,
      previousRecordHash: AUDIT_WITNESS_GENESIS_HASH,
      previousEventHash: AUDIT_WITNESS_GENESIS_HASH,
      eventHash: firstEventHash,
      occurredAtUtc: "2026-08-22T12:00:01.000Z",
      prepareRecordHash: AUDIT_WITNESS_GENESIS_HASH
    };
    const prepareHash = auditWitnessRecordHashV1(prepareCore);
    assert.equal(
      prepareHash,
      "4a243de58c26c7a2b53d3af7c37cdc7a8e9881feeda151b84557c3759756792c"
    );
    assert.equal(
      auditWitnessRecordHashV1({
        ...prepareCore,
        phase: "COMMIT",
        previousRecordHash: prepareHash,
        prepareRecordHash: prepareHash
      }),
      "13019704c881d23187c1094e7dd0bb19d73830272be573cbcbeba0a390d80ec0"
    );
  });

  it("requires PREPARE before database commit and a bound COMMIT afterwards", () => {
    const { genesis, prepare, state: preparedState } = prepared();
    assert.equal(prepare.phase, "PREPARE");
    assert.equal(preparedState.committedSequence, 0);
    assert.equal(preparedState.pendingPrepare?.recordHash, prepare.recordHash);

    assert.throws(
      () =>
        createAuditWitnessCommitV1({
          currentState: preparedState,
          observation: {
            databaseHeadSequence: 0,
            databaseHeadEventHash: AUDIT_WITNESS_GENESIS_HASH
          }
        }),
      /AUDIT_WITNESS_COMMIT_NOT_ALLOWED/
    );

    const commit = createAuditWitnessCommitV1({
      currentState: preparedState,
      observation: {
        databaseHeadSequence: 1,
        databaseHeadEventHash: firstEventHash
      }
    });
    const committed = advanceAuditWitnessStateV1({
      currentState: preparedState,
      record: commit
    });
    assert.equal(commit.phase, "COMMIT");
    assert.equal(commit.prepareRecordHash, prepare.recordHash);
    assert.deepEqual(committed, {
      chainId,
      committedSequence: 1,
      committedEventHash: firstEventHash,
      bootstrapSequence: 0,
      bootstrapEventHash: AUDIT_WITNESS_GENESIS_HASH,
      bootstrapCheckpointHash: AUDIT_WITNESS_GENESIS_HASH,
      bootstrapSignerPublicKeyFingerprintSha256:
        AUDIT_WITNESS_GENESIS_HASH,
      recordCount: 2,
      lastRecordHash: commit.recordHash,
      pendingPrepare: null
    });
    assert.deepEqual(
      reconcileAuditWitnessV1({
        state: committed,
        observation: {
          databaseHeadSequence: 1,
          databaseHeadEventHash: firstEventHash
        }
      }),
      {
        status: "consistent",
        appendCommitAllowed: false,
        operatorReviewRequired: false
      }
    );
    assert.equal(genesis.committedSequence, 0);
  });

  it("classifies only an existing durable PREPARE as recoverable", () => {
    const { state } = prepared();
    assert.deepEqual(
      reconcileAuditWitnessV1({
        state,
        observation: {
          databaseHeadSequence: 0,
          databaseHeadEventHash: AUDIT_WITNESS_GENESIS_HASH
        }
      }),
      {
        status: "prepare-not-database-committed",
        appendCommitAllowed: false,
        operatorReviewRequired: true,
        prepareRecordHash: state.pendingPrepare?.recordHash
      }
    );
    assert.equal(
      reconcileAuditWitnessV1({
        state,
        observation: {
          databaseHeadSequence: 1,
          databaseHeadEventHash: firstEventHash
        }
      }).status,
      "database-committed-awaiting-commit"
    );
    const aborted = createAuditWitnessAbortV1({
      currentState: state,
      operatorReviewConfirmed: true,
      observation: {
        databaseHeadSequence: 0,
        databaseHeadEventHash: AUDIT_WITNESS_GENESIS_HASH
      }
    });
    const recovered = advanceAuditWitnessStateV1({
      currentState: state,
      record: aborted
    });
    assert.equal(aborted.phase, "ABORT");
    assert.equal(recovered.committedSequence, 0);
    assert.equal(recovered.pendingPrepare, null);
    assert.equal(
      createAuditWitnessPrepareV1({
        currentState: recovered,
        eventHash: "d".repeat(64),
        occurredAtUtc: "2026-08-22T12:00:02.000Z"
      }).sequence,
      1
    );
    assert.throws(
      () =>
        createAuditWitnessAbortV1({
          currentState: state,
          operatorReviewConfirmed: false as true,
          observation: {
            databaseHeadSequence: 0,
            databaseHeadEventHash: AUDIT_WITNESS_GENESIS_HASH
          }
        }),
      /AUDIT_WITNESS_ABORT_OPERATOR_REVIEW_REQUIRED/
    );
    assert.throws(
      () =>
        reconcileAuditWitnessV1({
          state: createAuditWitnessGenesisStateV1(chainId),
          observation: {
            databaseHeadSequence: 1,
            databaseHeadEventHash: firstEventHash
          }
        }),
      /AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE/
    );
    assert.throws(
      () =>
        reconcileAuditWitnessV1({
          state: createAuditWitnessGenesisStateV1(chainId),
          observation: {
            databaseHeadSequence: 0,
            databaseHeadEventHash: firstEventHash
          }
        }),
      /AUDIT_WITNESS_DATABASE_OBSERVATION_INVALID/
    );
  });

  it("rejects fork, gap, replay, hash and commit-binding drift", () => {
    const { genesis, prepare, state } = prepared();
    const gapCore = { ...prepare, sequence: 2 };
    const gapWithoutHash = coreOf(gapCore);
    assert.throws(
      () =>
        advanceAuditWitnessStateV1({
          currentState: genesis,
          record: {
            ...gapWithoutHash,
            recordHash: auditWitnessRecordHashV1(gapWithoutHash)
          }
        }),
      /AUDIT_WITNESS_SEQUENCE_INVALID/
    );
    assert.throws(
      () =>
        advanceAuditWitnessStateV1({ currentState: state, record: prepare }),
      /AUDIT_WITNESS_RECORD_FORK_DETECTED/
    );
    assert.throws(
      () =>
        reconcileAuditWitnessV1({
          state,
          observation: {
            databaseHeadSequence: 1,
            databaseHeadEventHash: "c".repeat(64)
          }
        }),
      /AUDIT_WITNESS_DATABASE_FORK_DETECTED/
    );
    const commit = createAuditWitnessCommitV1({
      currentState: state,
      observation: {
        databaseHeadSequence: 1,
        databaseHeadEventHash: firstEventHash
      }
    });
    const bindingCore = {
      ...commit,
      prepareRecordHash: "c".repeat(64)
    };
    const bindingWithoutHash = coreOf(bindingCore);
    assert.throws(
      () =>
        advanceAuditWitnessStateV1({
          currentState: state,
          record: {
            ...bindingWithoutHash,
            recordHash: auditWitnessRecordHashV1(bindingWithoutHash)
          }
        }),
      /AUDIT_WITNESS_COMMIT_BINDING_INVALID/
    );
    const committed = advanceAuditWitnessStateV1({
      currentState: state,
      record: commit
    });
    assert.throws(
      () =>
        reconcileAuditWitnessV1({
          state: committed,
          observation: {
            databaseHeadSequence: 0,
            databaseHeadEventHash: AUDIT_WITNESS_GENESIS_HASH
          }
        }),
      /AUDIT_WITNESS_DATABASE_TRUNCATION_DETECTED/
    );
  });

  it("parses canonical LF records and quarantines but never truncates a torn tail", () => {
    const { prepare, state } = prepared();
    const commit = createAuditWitnessCommitV1({
      currentState: state,
      observation: {
        databaseHeadSequence: 1,
        databaseHeadEventHash: firstEventHash
      }
    });
    const complete = Buffer.concat([
      serializeAuditWitnessRecordV1(prepare),
      serializeAuditWitnessRecordV1(commit)
    ]);
    const parsed = parseAuditWitnessBytesV1({
      bytes: complete,
      expectedChainId: chainId
    });
    assert.equal(parsed.records.length, 2);
    assert.equal(parsed.state.committedSequence, 1);
    assert.equal(parsed.trailingTornBytes, null);

    const torn = Buffer.concat([complete, Buffer.from('{"phase":"PREP')]);
    const tornParsed = parseAuditWitnessBytesV1({
      bytes: torn,
      expectedChainId: chainId
    });
    assert.equal(tornParsed.state.committedSequence, 1);
    assert.deepEqual(tornParsed.trailingTornBytes, {
      byteLength: 14,
      sha256: "c7c679a9385155dc08b429decb884ae179b4f76c2cc1a176f48f7c67e2d7739d",
      quarantineRequired: true
    });

    const nonCanonical = Buffer.from(
      `${JSON.stringify({ ...prepare, extra: undefined })}\n`,
      "utf8"
    );
    assert.throws(
      () =>
        parseAuditWitnessBytesV1({
          bytes: nonCanonical,
          expectedChainId: chainId
        }),
      /AUDIT_WITNESS_CANONICAL_LINE_INVALID/
    );
    assert.throws(
      () =>
        parseAuditWitnessBytesV1({
          bytes: Buffer.from("{bad}\n", "utf8"),
          expectedChainId: chainId
        }),
      /AUDIT_WITNESS_LINE_INVALID/
    );
  });
});
