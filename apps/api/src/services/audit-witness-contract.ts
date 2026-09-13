import { z } from "zod";
import { sha256, stableJson } from "../domain/stable-json.js";

export const AUDIT_WITNESS_RECORD_PURPOSE_V1 =
  "project15.audit-witness-record.v1" as const;
export const AUDIT_WITNESS_CLAIM_V1 =
  "historical-rewrite-detection-only" as const;
export const AUDIT_WITNESS_BOOTSTRAP_PURPOSE_V1 =
  "project15.audit-witness-bootstrap.v1" as const;
export const AUDIT_WITNESS_GENESIS_HASH = "0".repeat(64);
export const AUDIT_WITNESS_MAXIMUM_BYTES = 1_048_576;
export const AUDIT_WITNESS_MAXIMUM_RECORDS = 4096;

const hashSchema = z.string().regex(/^[a-f0-9]{64}$/);
const nonGenesisHashSchema = hashSchema.refine(
  (value) => value !== AUDIT_WITNESS_GENESIS_HASH
);
const positiveSequenceSchema = z
  .number()
  .int()
  .min(1)
  .max(Number.MAX_SAFE_INTEGER);
const sequenceSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const canonicalUtcTimestampSchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
  .refine((value) => {
    const parsed = new Date(value);
    return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value;
  });

export const auditWitnessBootstrapAnchorCoreV1Schema = z
  .object({
    schemaVersion: z.literal(1),
    purpose: z.literal(AUDIT_WITNESS_BOOTSTRAP_PURPOSE_V1),
    chainId: nonGenesisHashSchema,
    sequence: positiveSequenceSchema,
    eventHash: nonGenesisHashSchema,
    checkpointHash: nonGenesisHashSchema,
    signerPublicKeyFingerprintSha256: nonGenesisHashSchema
  })
  .strict();

const commonCoreShape = {
  schemaVersion: z.literal(1),
  purpose: z.literal(AUDIT_WITNESS_RECORD_PURPOSE_V1),
  chainId: nonGenesisHashSchema,
  sequence: positiveSequenceSchema,
  previousRecordHash: hashSchema,
  previousEventHash: hashSchema,
  eventHash: nonGenesisHashSchema,
  occurredAtUtc: canonicalUtcTimestampSchema
};

export const auditWitnessPrepareCoreV1Schema = z
  .object({
    ...commonCoreShape,
    phase: z.literal("PREPARE"),
    prepareRecordHash: z.literal(AUDIT_WITNESS_GENESIS_HASH)
  })
  .strict();

export const auditWitnessCommitCoreV1Schema = z
  .object({
    ...commonCoreShape,
    phase: z.literal("COMMIT"),
    prepareRecordHash: nonGenesisHashSchema
  })
  .strict();

export const auditWitnessAbortCoreV1Schema = z
  .object({
    ...commonCoreShape,
    phase: z.literal("ABORT"),
    prepareRecordHash: nonGenesisHashSchema
  })
  .strict();

export const auditWitnessRecordCoreV1Schema = z.discriminatedUnion("phase", [
  auditWitnessPrepareCoreV1Schema,
  auditWitnessCommitCoreV1Schema,
  auditWitnessAbortCoreV1Schema
]);

export const auditWitnessRecordV1Schema = z.discriminatedUnion("phase", [
  auditWitnessPrepareCoreV1Schema.extend({ recordHash: nonGenesisHashSchema }),
  auditWitnessCommitCoreV1Schema.extend({ recordHash: nonGenesisHashSchema }),
  auditWitnessAbortCoreV1Schema.extend({ recordHash: nonGenesisHashSchema })
]);

const pendingPrepareV1Schema = z
  .object({
    sequence: positiveSequenceSchema,
    previousEventHash: hashSchema,
    eventHash: nonGenesisHashSchema,
    occurredAtUtc: canonicalUtcTimestampSchema,
    recordHash: nonGenesisHashSchema
  })
  .strict();

export const auditWitnessStateV1Schema = z
  .object({
    chainId: nonGenesisHashSchema,
    committedSequence: sequenceSchema,
    committedEventHash: hashSchema,
    bootstrapSequence: sequenceSchema,
    bootstrapEventHash: hashSchema,
    bootstrapCheckpointHash: hashSchema,
    bootstrapSignerPublicKeyFingerprintSha256: hashSchema,
    recordCount: sequenceSchema,
    lastRecordHash: hashSchema,
    pendingPrepare: pendingPrepareV1Schema.nullable()
  })
  .strict();

export const auditWitnessDatabaseObservationV1Schema = z
  .object({
    databaseHeadSequence: sequenceSchema,
    databaseHeadEventHash: hashSchema
  })
  .strict();

export type AuditWitnessRecordCoreV1 = z.infer<
  typeof auditWitnessRecordCoreV1Schema
>;
export type AuditWitnessBootstrapAnchorCoreV1 = z.infer<
  typeof auditWitnessBootstrapAnchorCoreV1Schema
>;
export type AuditWitnessRecordV1 = z.infer<typeof auditWitnessRecordV1Schema>;
export type AuditWitnessStateV1 = z.infer<typeof auditWitnessStateV1Schema>;
export type AuditWitnessDatabaseObservationV1 = z.infer<
  typeof auditWitnessDatabaseObservationV1Schema
>;

export type AuditWitnessReconciliationV1 =
  | {
      status: "consistent";
      appendCommitAllowed: false;
      operatorReviewRequired: false;
    }
  | {
      status: "prepare-not-database-committed";
      appendCommitAllowed: false;
      operatorReviewRequired: true;
      prepareRecordHash: string;
    }
  | {
      status: "database-committed-awaiting-commit";
      appendCommitAllowed: true;
      operatorReviewRequired: false;
      prepareRecordHash: string;
    };

export type ParsedAuditWitnessV1 = {
  records: AuditWitnessRecordV1[];
  state: AuditWitnessStateV1;
  trailingTornBytes: null | {
    byteLength: number;
    sha256: string;
    quarantineRequired: true;
  };
};

function fail(code: string): never {
  throw new Error(code);
}

function recordCore(record: AuditWitnessRecordV1): AuditWitnessRecordCoreV1 {
  return auditWitnessRecordCoreV1Schema.parse({
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
  });
}

function validateState(value: unknown): AuditWitnessStateV1 {
  let state: AuditWitnessStateV1;
  try {
    state = auditWitnessStateV1Schema.parse(value);
  } catch {
    return fail("AUDIT_WITNESS_STATE_INVALID");
  }

  const hasCheckpointBootstrap =
    state.bootstrapCheckpointHash !== AUDIT_WITNESS_GENESIS_HASH;
  let bootstrapAnchorHash = AUDIT_WITNESS_GENESIS_HASH;
  if (hasCheckpointBootstrap) {
    try {
      bootstrapAnchorHash = auditWitnessBootstrapAnchorHashV1({
        schemaVersion: 1,
        purpose: AUDIT_WITNESS_BOOTSTRAP_PURPOSE_V1,
        chainId: state.chainId,
        sequence: state.bootstrapSequence,
        eventHash: state.bootstrapEventHash,
        checkpointHash: state.bootstrapCheckpointHash,
        signerPublicKeyFingerprintSha256:
          state.bootstrapSignerPublicKeyFingerprintSha256
      });
    } catch {
      return fail("AUDIT_WITNESS_STATE_INVALID");
    }
  }
  if (
    (state.committedSequence === 0) !==
      (state.committedEventHash === AUDIT_WITNESS_GENESIS_HASH) ||
    (!hasCheckpointBootstrap &&
      (state.bootstrapSequence !== 0 ||
        state.bootstrapEventHash !== AUDIT_WITNESS_GENESIS_HASH ||
        state.bootstrapSignerPublicKeyFingerprintSha256 !==
          AUDIT_WITNESS_GENESIS_HASH)) ||
    (hasCheckpointBootstrap &&
      (state.bootstrapSequence < 1 ||
        state.bootstrapEventHash === AUDIT_WITNESS_GENESIS_HASH ||
        state.bootstrapSignerPublicKeyFingerprintSha256 ===
          AUDIT_WITNESS_GENESIS_HASH ||
        state.committedSequence < state.bootstrapSequence)) ||
    (state.recordCount === 0 &&
      (state.pendingPrepare !== null ||
        state.committedSequence !== state.bootstrapSequence ||
        state.committedEventHash !== state.bootstrapEventHash ||
        state.lastRecordHash !== bootstrapAnchorHash)) ||
    (state.recordCount > 0 &&
      state.lastRecordHash === AUDIT_WITNESS_GENESIS_HASH) ||
    (state.committedSequence > 0 &&
      state.committedEventHash === AUDIT_WITNESS_GENESIS_HASH) ||
    (state.committedSequence > 0 &&
      state.lastRecordHash === AUDIT_WITNESS_GENESIS_HASH)
  ) {
    return fail("AUDIT_WITNESS_STATE_INVALID");
  }

  const pending = state.pendingPrepare;
  if (
    pending !== null &&
    (pending.sequence !== state.committedSequence + 1 ||
      pending.previousEventHash !== state.committedEventHash ||
      pending.recordHash !== state.lastRecordHash)
  ) {
    return fail("AUDIT_WITNESS_STATE_INVALID");
  }
  return state;
}

export function createAuditWitnessGenesisStateV1(
  chainId: string
): AuditWitnessStateV1 {
  let parsedChainId: string;
  try {
    parsedChainId = nonGenesisHashSchema.parse(chainId);
  } catch {
    return fail("AUDIT_WITNESS_CHAIN_INVALID");
  }
  return {
    chainId: parsedChainId,
    committedSequence: 0,
    committedEventHash: AUDIT_WITNESS_GENESIS_HASH,
    bootstrapSequence: 0,
    bootstrapEventHash: AUDIT_WITNESS_GENESIS_HASH,
    bootstrapCheckpointHash: AUDIT_WITNESS_GENESIS_HASH,
    bootstrapSignerPublicKeyFingerprintSha256: AUDIT_WITNESS_GENESIS_HASH,
    recordCount: 0,
    lastRecordHash: AUDIT_WITNESS_GENESIS_HASH,
    pendingPrepare: null
  };
}

export function auditWitnessBootstrapAnchorHashV1(
  core: AuditWitnessBootstrapAnchorCoreV1
): string {
  return sha256(
    stableJson(auditWitnessBootstrapAnchorCoreV1Schema.parse(core))
  );
}

export function createAuditWitnessCheckpointBootstrapStateV1(
  core: AuditWitnessBootstrapAnchorCoreV1
): AuditWitnessStateV1 {
  let parsed: AuditWitnessBootstrapAnchorCoreV1;
  try {
    parsed = auditWitnessBootstrapAnchorCoreV1Schema.parse(core);
  } catch {
    return fail("AUDIT_WITNESS_BOOTSTRAP_SCHEMA_INVALID");
  }
  return validateState({
    chainId: parsed.chainId,
    committedSequence: parsed.sequence,
    committedEventHash: parsed.eventHash,
    bootstrapSequence: parsed.sequence,
    bootstrapEventHash: parsed.eventHash,
    bootstrapCheckpointHash: parsed.checkpointHash,
    bootstrapSignerPublicKeyFingerprintSha256:
      parsed.signerPublicKeyFingerprintSha256,
    recordCount: 0,
    lastRecordHash: auditWitnessBootstrapAnchorHashV1(parsed),
    pendingPrepare: null
  });
}

export function auditWitnessRecordHashV1(
  core: AuditWitnessRecordCoreV1
): string {
  return sha256(stableJson(auditWitnessRecordCoreV1Schema.parse(core)));
}

export function createAuditWitnessPrepareV1(input: {
  currentState: unknown;
  eventHash: string;
  occurredAtUtc: string;
}): AuditWitnessRecordV1 {
  const state = validateState(input.currentState);
  if (state.pendingPrepare !== null) {
    return fail("AUDIT_WITNESS_PREPARE_ALREADY_PENDING");
  }

  let eventHash: string;
  let occurredAtUtc: string;
  try {
    eventHash = nonGenesisHashSchema.parse(input.eventHash);
    occurredAtUtc = canonicalUtcTimestampSchema.parse(input.occurredAtUtc);
  } catch {
    return fail("AUDIT_WITNESS_EVENT_INVALID");
  }

  const core: AuditWitnessRecordCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_WITNESS_RECORD_PURPOSE_V1,
    phase: "PREPARE",
    chainId: state.chainId,
    sequence: state.committedSequence + 1,
    previousRecordHash: state.lastRecordHash,
    previousEventHash: state.committedEventHash,
    eventHash,
    occurredAtUtc,
    prepareRecordHash: AUDIT_WITNESS_GENESIS_HASH
  };
  return auditWitnessRecordV1Schema.parse({
    ...core,
    recordHash: auditWitnessRecordHashV1(core)
  });
}

export function createAuditWitnessCommitV1(input: {
  currentState: unknown;
  observation: unknown;
}): AuditWitnessRecordV1 {
  const state = validateState(input.currentState);
  const reconciliation = reconcileAuditWitnessV1({
    state,
    observation: input.observation
  });
  const pending = state.pendingPrepare;
  if (
    reconciliation.status !== "database-committed-awaiting-commit" ||
    pending === null
  ) {
    return fail("AUDIT_WITNESS_COMMIT_NOT_ALLOWED");
  }

  const core: AuditWitnessRecordCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_WITNESS_RECORD_PURPOSE_V1,
    phase: "COMMIT",
    chainId: state.chainId,
    sequence: pending.sequence,
    previousRecordHash: pending.recordHash,
    previousEventHash: pending.previousEventHash,
    eventHash: pending.eventHash,
    occurredAtUtc: pending.occurredAtUtc,
    prepareRecordHash: pending.recordHash
  };
  return auditWitnessRecordV1Schema.parse({
    ...core,
    recordHash: auditWitnessRecordHashV1(core)
  });
}

export function createAuditWitnessAbortV1(input: {
  currentState: unknown;
  observation: unknown;
  operatorReviewConfirmed: true;
}): AuditWitnessRecordV1 {
  if (input.operatorReviewConfirmed !== true) {
    return fail("AUDIT_WITNESS_ABORT_OPERATOR_REVIEW_REQUIRED");
  }
  const state = validateState(input.currentState);
  const reconciliation = reconcileAuditWitnessV1({
    state,
    observation: input.observation
  });
  const pending = state.pendingPrepare;
  if (
    reconciliation.status !== "prepare-not-database-committed" ||
    pending === null
  ) {
    return fail("AUDIT_WITNESS_ABORT_NOT_ALLOWED");
  }

  const core: AuditWitnessRecordCoreV1 = {
    schemaVersion: 1,
    purpose: AUDIT_WITNESS_RECORD_PURPOSE_V1,
    phase: "ABORT",
    chainId: state.chainId,
    sequence: pending.sequence,
    previousRecordHash: pending.recordHash,
    previousEventHash: pending.previousEventHash,
    eventHash: pending.eventHash,
    occurredAtUtc: pending.occurredAtUtc,
    prepareRecordHash: pending.recordHash
  };
  return auditWitnessRecordV1Schema.parse({
    ...core,
    recordHash: auditWitnessRecordHashV1(core)
  });
}

export function advanceAuditWitnessStateV1(input: {
  currentState: unknown;
  record: unknown;
}): AuditWitnessStateV1 {
  const state = validateState(input.currentState);
  let record: AuditWitnessRecordV1;
  try {
    record = auditWitnessRecordV1Schema.parse(input.record);
  } catch {
    return fail("AUDIT_WITNESS_RECORD_SCHEMA_INVALID");
  }

  if (record.chainId !== state.chainId) {
    return fail("AUDIT_WITNESS_CHAIN_MISMATCH");
  }
  if (record.recordHash !== auditWitnessRecordHashV1(recordCore(record))) {
    return fail("AUDIT_WITNESS_RECORD_HASH_INVALID");
  }
  if (record.previousRecordHash !== state.lastRecordHash) {
    return fail("AUDIT_WITNESS_RECORD_FORK_DETECTED");
  }

  if (record.phase === "PREPARE") {
    if (state.pendingPrepare !== null) {
      return fail("AUDIT_WITNESS_PREPARE_ALREADY_PENDING");
    }
    if (
      record.sequence !== state.committedSequence + 1 ||
      record.previousEventHash !== state.committedEventHash
    ) {
      return fail("AUDIT_WITNESS_SEQUENCE_INVALID");
    }
    return validateState({
      ...state,
      recordCount: state.recordCount + 1,
      lastRecordHash: record.recordHash,
      pendingPrepare: {
        sequence: record.sequence,
        previousEventHash: record.previousEventHash,
        eventHash: record.eventHash,
        occurredAtUtc: record.occurredAtUtc,
        recordHash: record.recordHash
      }
    });
  }

  const pending = state.pendingPrepare;
  if (pending === null) return fail("AUDIT_WITNESS_COMMIT_WITHOUT_PREPARE");
  if (
    record.sequence !== pending.sequence ||
    record.previousEventHash !== pending.previousEventHash ||
    record.eventHash !== pending.eventHash ||
    record.occurredAtUtc !== pending.occurredAtUtc ||
    record.prepareRecordHash !== pending.recordHash ||
    record.previousRecordHash !== pending.recordHash
  ) {
    return fail(
      record.phase === "ABORT"
        ? "AUDIT_WITNESS_ABORT_BINDING_INVALID"
        : "AUDIT_WITNESS_COMMIT_BINDING_INVALID"
    );
  }
  if (record.phase === "ABORT") {
    return validateState({
      ...state,
      recordCount: state.recordCount + 1,
      lastRecordHash: record.recordHash,
      pendingPrepare: null
    });
  }
  return validateState({
    chainId: state.chainId,
    committedSequence: record.sequence,
    committedEventHash: record.eventHash,
    bootstrapSequence: state.bootstrapSequence,
    bootstrapEventHash: state.bootstrapEventHash,
    bootstrapCheckpointHash: state.bootstrapCheckpointHash,
    bootstrapSignerPublicKeyFingerprintSha256:
      state.bootstrapSignerPublicKeyFingerprintSha256,
    recordCount: state.recordCount + 1,
    lastRecordHash: record.recordHash,
    pendingPrepare: null
  });
}

export function reconcileAuditWitnessV1(input: {
  state: unknown;
  observation: unknown;
}): AuditWitnessReconciliationV1 {
  const state = validateState(input.state);
  let observation: AuditWitnessDatabaseObservationV1;
  try {
    observation = auditWitnessDatabaseObservationV1Schema.parse(input.observation);
  } catch {
    return fail("AUDIT_WITNESS_DATABASE_OBSERVATION_INVALID");
  }
  if (
    (observation.databaseHeadSequence === 0) !==
    (observation.databaseHeadEventHash === AUDIT_WITNESS_GENESIS_HASH)
  ) {
    return fail("AUDIT_WITNESS_DATABASE_OBSERVATION_INVALID");
  }

  if (observation.databaseHeadSequence < state.committedSequence) {
    return fail("AUDIT_WITNESS_DATABASE_TRUNCATION_DETECTED");
  }
  if (
    observation.databaseHeadSequence === state.committedSequence &&
    observation.databaseHeadEventHash !== state.committedEventHash
  ) {
    return fail("AUDIT_WITNESS_DATABASE_FORK_DETECTED");
  }

  const pending = state.pendingPrepare;
  if (pending === null) {
    if (observation.databaseHeadSequence !== state.committedSequence) {
      return fail("AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE");
    }
    return {
      status: "consistent",
      appendCommitAllowed: false,
      operatorReviewRequired: false
    };
  }

  if (observation.databaseHeadSequence === state.committedSequence) {
    return {
      status: "prepare-not-database-committed",
      appendCommitAllowed: false,
      operatorReviewRequired: true,
      prepareRecordHash: pending.recordHash
    };
  }
  if (
    observation.databaseHeadSequence === pending.sequence &&
    observation.databaseHeadEventHash === pending.eventHash
  ) {
    return {
      status: "database-committed-awaiting-commit",
      appendCommitAllowed: true,
      operatorReviewRequired: false,
      prepareRecordHash: pending.recordHash
    };
  }
  if (observation.databaseHeadSequence === pending.sequence) {
    return fail("AUDIT_WITNESS_DATABASE_FORK_DETECTED");
  }
  return fail("AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE");
}

export function serializeAuditWitnessRecordV1(
  value: unknown
): Uint8Array {
  let record: AuditWitnessRecordV1;
  try {
    record = auditWitnessRecordV1Schema.parse(value);
  } catch {
    return fail("AUDIT_WITNESS_RECORD_SCHEMA_INVALID");
  }
  if (record.recordHash !== auditWitnessRecordHashV1(recordCore(record))) {
    return fail("AUDIT_WITNESS_RECORD_HASH_INVALID");
  }
  return Buffer.from(`${stableJson(record)}\n`, "utf8");
}

export function parseAuditWitnessBytesV1(input: {
  bytes: Uint8Array;
  expectedChainId?: string;
  initialState?: unknown;
}): ParsedAuditWitnessV1 {
  if (input.bytes.byteLength > AUDIT_WITNESS_MAXIMUM_BYTES) {
    return fail("AUDIT_WITNESS_BYTES_INVALID");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(input.bytes);
  } catch {
    return fail("AUDIT_WITNESS_UTF8_INVALID");
  }
  if (text.startsWith("\uFEFF") || text.includes("\r") || text.includes("\0")) {
    return fail("AUDIT_WITNESS_ENCODING_INVALID");
  }

  const complete = text.endsWith("\n");
  const lines = text.split("\n");
  const tornText = complete ? "" : (lines.pop() ?? "");
  if (complete) lines.pop();
  if (lines.some((line) => line.length === 0)) {
    return fail("AUDIT_WITNESS_LINE_INVALID");
  }
  if (lines.length > AUDIT_WITNESS_MAXIMUM_RECORDS) {
    return fail("AUDIT_WITNESS_RECORD_LIMIT_EXCEEDED");
  }

  if (
    (input.expectedChainId === undefined) ===
    (input.initialState === undefined)
  ) {
    return fail("AUDIT_WITNESS_INITIAL_STATE_INVALID");
  }
  let state =
    input.initialState === undefined
      ? createAuditWitnessGenesisStateV1(input.expectedChainId ?? "")
      : validateState(input.initialState);
  const records: AuditWitnessRecordV1[] = [];
  for (const line of lines) {
    let unknownRecord: unknown;
    try {
      unknownRecord = JSON.parse(line);
    } catch {
      return fail("AUDIT_WITNESS_LINE_INVALID");
    }
    let record: AuditWitnessRecordV1;
    try {
      record = auditWitnessRecordV1Schema.parse(unknownRecord);
    } catch {
      return fail("AUDIT_WITNESS_RECORD_SCHEMA_INVALID");
    }
    if (stableJson(record) !== line) {
      return fail("AUDIT_WITNESS_CANONICAL_LINE_INVALID");
    }
    state = advanceAuditWitnessStateV1({ currentState: state, record });
    records.push(record);
  }

  const tornBytes = Buffer.from(tornText, "utf8");
  return {
    records,
    state,
    trailingTornBytes:
      tornBytes.byteLength === 0
        ? null
        : {
            byteLength: tornBytes.byteLength,
            sha256: sha256(tornBytes),
            quarantineRequired: true
          }
  };
}
