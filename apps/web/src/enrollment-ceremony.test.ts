import assert from "node:assert/strict";
import test from "node:test";
import {
  parseEnrollmentIdentity,
  parseEnrollmentProof,
  parseSignedCapabilityReport,
  SCM_COLLECTOR_VERSION,
  SCM_FIELDS,
  SCM_FILTER_HASH,
  stableJson,
  validateAcceptedCapability,
  validateApprovedEndpointIdentity,
  validateCapabilityReportHash,
  validateRegisteredEnrollmentKey,
  validateEnrollmentChallenge
} from "./enrollment-ceremony";

const fingerprint = "a".repeat(64);
const publicKey = "A".repeat(88);
const missionId = "11111111-1111-4111-8111-111111111111";

const identityJson = JSON.stringify({
  ok: true,
  command: "enrollment-identity",
  identity: {
    algorithm: "ecdsa-p256-sha256",
    publicKeyFormat: "spki-der",
    publicKeySpkiBase64: publicKey,
    certificateFingerprintSha256: fingerprint,
    keyProvider: "Microsoft Software Key Storage Provider",
    keyPersistence: "non-exportable-machine-cng-software-ksp"
  },
  privateExportBlocked: true,
  commandChannelEnabled: false
});

function fixture() {
  const identity = parseEnrollmentIdentity(identityJson);
  const payload = {
    schemaVersion: 1,
    challengeId: "enrollment-22222222-2222-4222-8222-222222222222",
    missionId,
    connectorId: "connector-33333333-3333-4333-8333-333333333333",
    endpointId: "endpoint-44444444-4444-4444-8444-444444444444",
    certificateFingerprintSha256: fingerprint,
    nonceBase64Url: "A".repeat(43),
    requestedAt: "2026-08-03T10:00:00.000Z",
    challengeExpiresAt: "2026-08-03T10:05:00.000Z",
    identityExpiresAt: "2026-08-09T10:00:00.000Z"
  };
  const challenge = validateEnrollmentChallenge({
    id: payload.challengeId,
    status: "pending",
    payload,
    challengeHash: "b".repeat(64)
  }, identity, missionId);
  return { identity, challenge };
}

test("accepts only the fixed native identity profile and bound proof", () => {
  const { identity, challenge } = fixture();
  const proof = parseEnrollmentProof(JSON.stringify({
    ok: true,
    command: "sign-enrollment-challenge",
    result: {
      schemaVersion: 1,
      challengeId: challenge.id,
      challengeHash: challenge.challengeHash,
      certificateFingerprintSha256: fingerprint,
      publicKeySpkiBase64: publicKey,
      canonicalPayload: stableJson(challenge.payload),
      proofSignatureBase64: "A".repeat(88),
      challengeExpiresAt: challenge.payload.challengeExpiresAt,
      identityExpiresAt: challenge.payload.identityExpiresAt
    },
    commandChannelEnabled: false
  }), challenge, identity);
  assert.equal(proof.challengeId, challenge.id);
});

test("rejects extra identity authority and proof rebinding", () => {
  const expanded = JSON.parse(identityJson) as Record<string, unknown>;
  expanded.commandChannel = "enabled";
  assert.throws(() => parseEnrollmentIdentity(JSON.stringify(expanded)), /ENROLLMENT_IDENTITY_FIELDS_INVALID/);

  const { identity, challenge } = fixture();
  const wrongProof = {
    ok: true,
    command: "sign-enrollment-challenge",
    result: {
      schemaVersion: 1,
      challengeId: challenge.id,
      challengeHash: "c".repeat(64),
      certificateFingerprintSha256: fingerprint,
      publicKeySpkiBase64: publicKey,
      canonicalPayload: stableJson(challenge.payload),
      proofSignatureBase64: "A".repeat(88),
      challengeExpiresAt: challenge.payload.challengeExpiresAt,
      identityExpiresAt: challenge.payload.identityExpiresAt
    },
    commandChannelEnabled: false
  };
  assert.throws(() => parseEnrollmentProof(JSON.stringify(wrongProof), challenge, identity), /ENROLLMENT_PROOF_BINDING_INVALID/);
});

test("rebinds registered key and approved identity responses", () => {
  const { identity, challenge } = fixture();
  validateRegisteredEnrollmentKey({
    algorithm: identity.algorithm,
    publicKeyFormat: identity.publicKeyFormat,
    certificateFingerprintSha256: fingerprint,
    endpointId: challenge.payload.endpointId,
    enrollmentChallengeId: challenge.id,
    registeredAt: "2026-08-03T10:00:01.000Z"
  }, challenge, identity);
  const endpoint = {
    endpointId: challenge.payload.endpointId,
    connectorId: challenge.payload.connectorId,
    missionId,
    certificateFingerprintSha256: fingerprint,
    enrollmentChallengeId: challenge.id,
    status: "active",
    issuedAt: "2026-08-03T10:01:00.000Z",
    expiresAt: challenge.payload.identityExpiresAt,
    approvedBy: "operator",
    revokedAt: null,
    revokedBy: null,
    revocationReason: null,
    currentBootId: null,
    lastSequence: null,
    lastBatchHash: null,
    lastReceiptHash: null,
    lastSeenAt: null
  };
  assert.equal(validateApprovedEndpointIdentity(endpoint, challenge).endpointId, challenge.payload.endpointId);
  assert.throws(() => validateApprovedEndpointIdentity({ ...endpoint, connectorId: "connector-55555555-5555-4555-8555-555555555555" }, challenge), /ENROLLMENT_ENDPOINT_BINDING_INVALID/);
});

test("binds the signed capability report and accepted snapshot", async () => {
  const { challenge } = fixture();
  const observedAt = new Date(Date.now() - 10_000).toISOString();
  const freshUntil = new Date(Date.parse(observedAt) + 300_000).toISOString();
  const endpoint = validateApprovedEndpointIdentity({
    endpointId: challenge.payload.endpointId,
    connectorId: challenge.payload.connectorId,
    missionId,
    certificateFingerprintSha256: fingerprint,
    enrollmentChallengeId: challenge.id,
    status: "active",
    issuedAt: "2026-08-03T10:01:00.000Z",
    expiresAt: challenge.payload.identityExpiresAt,
    approvedBy: "operator",
    revokedAt: null,
    revokedBy: null,
    revocationReason: null,
    currentBootId: null,
    lastSequence: null,
    lastBatchHash: null,
    lastReceiptHash: null,
    lastSeenAt: null
  }, challenge);
  const core = {
    schemaVersion: 1,
    missionId,
    connectorId: endpoint.connectorId,
    endpointId: endpoint.endpointId,
    certificateFingerprintSha256: fingerprint,
    provider: "windows-scm",
    channel: "system",
    eventFamily: "service-change",
    fields: [...SCM_FIELDS],
    filterHash: SCM_FILTER_HASH,
    collectorVersion: SCM_COLLECTOR_VERSION,
    loss: { state: "unknown", lostRecordCount: null },
    continuity: "unknown",
    continuousSince: observedAt,
    lastSuccessfulReadAt: observedAt,
    observedAt,
    freshnessSeconds: 300
  };
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stableJson(core)));
  const reportHash = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const report = parseSignedCapabilityReport(JSON.stringify({ ...core, reportHash, signatureBase64: "A".repeat(88) }), endpoint);
  await validateCapabilityReportHash(report);
  const capability = validateAcceptedCapability({
    id: "capability-55555555-5555-4555-8555-555555555555",
    reportHash,
    missionId: core.missionId,
    connectorId: core.connectorId,
    endpointId: core.endpointId,
    certificateFingerprintSha256: core.certificateFingerprintSha256,
    provider: core.provider,
    channel: core.channel,
    eventFamily: core.eventFamily,
    fields: core.fields,
    fieldsHash: "c".repeat(64),
    filterHash: core.filterHash,
    collectorVersion: core.collectorVersion,
    loss: core.loss,
    continuity: core.continuity,
    continuousSince: core.continuousSince,
    lastSuccessfulReadAt: core.lastSuccessfulReadAt,
    observedAt: core.observedAt,
    freshUntil,
    evidenceArtifactId: "66666666-6666-4666-8666-666666666666",
    recordedAt: observedAt,
    health: "degraded",
    limitation: "One-shot access cannot prove loss-free continuity; coverage remains blocked."
  }, report);
  assert.equal(capability.id, "capability-55555555-5555-4555-8555-555555555555");
  assert.throws(() => parseSignedCapabilityReport(JSON.stringify({ ...core, reportHash, signatureBase64: "A".repeat(88), command: "run" }), endpoint), /CAPABILITY_REPORT_FIELDS_INVALID/);
});
