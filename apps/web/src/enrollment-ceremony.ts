const FINGERPRINT = /^[a-f0-9]{64}$/;
const BASE64 = /^[A-Za-z0-9+/=]+$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const CHALLENGE_ID = /^enrollment-[a-f0-9-]{36}$/;
const CONNECTOR_ID = /^connector-[a-f0-9-]{36}$/;
const ENDPOINT_ID = /^endpoint-[a-f0-9-]{36}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const UTC_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const SCM_FILTER_HASH = "89d3e1f9a63f38a94c640fb5555e59cd23d74bc5bef77059473c67c3516f3063";
export const SCM_COLLECTOR_VERSION = "windows-sensor-0.1.0";
export const SCM_FIELDS = ["action", "actorTrust", "objectClass", "outcome", "subjectClass"] as const;

export interface NativeEnrollmentIdentity {
  algorithm: "ecdsa-p256-sha256";
  publicKeyFormat: "spki-der";
  publicKeySpkiBase64: string;
  certificateFingerprintSha256: string;
  keyProvider: "Microsoft Software Key Storage Provider";
  keyPersistence: "non-exportable-machine-cng-software-ksp";
}

export interface EnrollmentChallengePayload {
  schemaVersion: 1;
  challengeId: string;
  missionId: string;
  connectorId: string;
  endpointId: string;
  certificateFingerprintSha256: string;
  nonceBase64Url: string;
  requestedAt: string;
  challengeExpiresAt: string;
  identityExpiresAt: string;
}

export interface EnrollmentChallenge {
  id: string;
  status: "pending";
  payload: EnrollmentChallengePayload;
  challengeHash: string;
}

export interface NativeEnrollmentProof {
  schemaVersion: 1;
  challengeId: string;
  challengeHash: string;
  certificateFingerprintSha256: string;
  publicKeySpkiBase64: string;
  canonicalPayload: string;
  proofSignatureBase64: string;
  challengeExpiresAt: string;
  identityExpiresAt: string;
}

export interface RegisteredEnrollmentKey {
  algorithm: "ecdsa-p256-sha256";
  publicKeyFormat: "spki-der";
  certificateFingerprintSha256: string;
  endpointId: string;
  enrollmentChallengeId: string;
  registeredAt: string;
}

export interface ApprovedEndpointIdentity {
  endpointId: string;
  connectorId: string;
  missionId: string;
  certificateFingerprintSha256: string;
  enrollmentChallengeId: string;
  status: "active";
  issuedAt: string;
  expiresAt: string;
  approvedBy: string;
}

export interface SignedCapabilityReport {
  schemaVersion: 1;
  missionId: string;
  connectorId: string;
  endpointId: string;
  certificateFingerprintSha256: string;
  provider: "windows-scm";
  channel: "system";
  eventFamily: "service-change";
  fields: string[];
  filterHash: string;
  collectorVersion: string;
  loss: { state: "unknown"; lostRecordCount: null };
  continuity: "unknown";
  continuousSince: string;
  lastSuccessfulReadAt: string;
  observedAt: string;
  freshnessSeconds: 300;
  reportHash: string;
  signatureBase64: string;
}

export interface AcceptedCapability {
  id: string;
  reportHash: string;
  missionId: string;
  connectorId: string;
  endpointId: string;
  certificateFingerprintSha256: string;
  provider: "windows-scm";
  channel: "system";
  eventFamily: "service-change";
  fields: string[];
  filterHash: string;
  collectorVersion: string;
  freshUntil: string;
  health: "degraded";
  evidenceArtifactId: string;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("ENROLLMENT_JSON_OBJECT_REQUIRED");
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, keys: readonly string[], code: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(code);
  }
}

function text(value: unknown, pattern: RegExp, code: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(code);
  return value;
}

function parseJson(input: string, maximumLength: number): unknown {
  if (input.length < 2 || input.length > maximumLength) throw new Error("ENROLLMENT_JSON_SIZE_INVALID");
  try {
    return JSON.parse(input) as unknown;
  } catch {
    throw new Error("ENROLLMENT_JSON_INVALID");
  }
}

export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    const item = value as Record<string, unknown>;
    return `{${Object.keys(item).sort().map((key) => `${JSON.stringify(key)}:${stableJson(item[key])}`).join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("ENROLLMENT_CANONICAL_VALUE_INVALID");
  return encoded;
}

export function parseEnrollmentIdentity(input: string): NativeEnrollmentIdentity {
  const wrapper = record(parseJson(input, 16_384));
  exact(wrapper, ["ok", "command", "identity", "privateExportBlocked", "commandChannelEnabled"], "ENROLLMENT_IDENTITY_FIELDS_INVALID");
  if (wrapper.ok !== true || wrapper.command !== "enrollment-identity" || wrapper.privateExportBlocked !== true || wrapper.commandChannelEnabled !== false) {
    throw new Error("ENROLLMENT_IDENTITY_BOUNDARY_INVALID");
  }
  const identity = record(wrapper.identity);
  exact(identity, ["algorithm", "publicKeyFormat", "publicKeySpkiBase64", "certificateFingerprintSha256", "keyProvider", "keyPersistence"], "ENROLLMENT_IDENTITY_FIELDS_INVALID");
  if (identity.algorithm !== "ecdsa-p256-sha256" || identity.publicKeyFormat !== "spki-der" || identity.keyProvider !== "Microsoft Software Key Storage Provider" || identity.keyPersistence !== "non-exportable-machine-cng-software-ksp") {
    throw new Error("ENROLLMENT_IDENTITY_PROFILE_INVALID");
  }
  const publicKeySpkiBase64 = text(identity.publicKeySpkiBase64, BASE64, "ENROLLMENT_PUBLIC_KEY_INVALID");
  if (publicKeySpkiBase64.length < 56 || publicKeySpkiBase64.length > 4_096) throw new Error("ENROLLMENT_PUBLIC_KEY_INVALID");
  return {
    algorithm: identity.algorithm,
    publicKeyFormat: identity.publicKeyFormat,
    publicKeySpkiBase64,
    certificateFingerprintSha256: text(identity.certificateFingerprintSha256, FINGERPRINT, "ENROLLMENT_FINGERPRINT_INVALID"),
    keyProvider: identity.keyProvider,
    keyPersistence: identity.keyPersistence
  };
}

export function validateEnrollmentChallenge(value: unknown, identity: NativeEnrollmentIdentity, missionId: string): EnrollmentChallenge {
  const challenge = record(value);
  exact(challenge, ["id", "status", "payload", "challengeHash"], "ENROLLMENT_CHALLENGE_FIELDS_INVALID");
  const payload = record(challenge.payload);
  exact(payload, ["schemaVersion", "challengeId", "missionId", "connectorId", "endpointId", "certificateFingerprintSha256", "nonceBase64Url", "requestedAt", "challengeExpiresAt", "identityExpiresAt"], "ENROLLMENT_CHALLENGE_FIELDS_INVALID");
  const challengeId = text(payload.challengeId, CHALLENGE_ID, "ENROLLMENT_CHALLENGE_INVALID");
  const parsed = {
    schemaVersion: payload.schemaVersion,
    challengeId,
    missionId: text(payload.missionId, UUID, "ENROLLMENT_MISSION_INVALID"),
    connectorId: text(payload.connectorId, CONNECTOR_ID, "ENROLLMENT_CONNECTOR_INVALID"),
    endpointId: text(payload.endpointId, ENDPOINT_ID, "ENROLLMENT_ENDPOINT_INVALID"),
    certificateFingerprintSha256: text(payload.certificateFingerprintSha256, FINGERPRINT, "ENROLLMENT_FINGERPRINT_INVALID"),
    nonceBase64Url: text(payload.nonceBase64Url, NONCE, "ENROLLMENT_NONCE_INVALID"),
    requestedAt: text(payload.requestedAt, UTC_MILLISECONDS, "ENROLLMENT_TIME_INVALID"),
    challengeExpiresAt: text(payload.challengeExpiresAt, UTC_MILLISECONDS, "ENROLLMENT_TIME_INVALID"),
    identityExpiresAt: text(payload.identityExpiresAt, UTC_MILLISECONDS, "ENROLLMENT_TIME_INVALID")
  };
  if (parsed.schemaVersion !== 1 || challenge.status !== "pending" || challenge.id !== challengeId || parsed.missionId !== missionId || parsed.certificateFingerprintSha256 !== identity.certificateFingerprintSha256) {
    throw new Error("ENROLLMENT_CHALLENGE_BINDING_INVALID");
  }
  text(challenge.challengeHash, FINGERPRINT, "ENROLLMENT_CHALLENGE_HASH_INVALID");
  return { id: challengeId, status: "pending", payload: parsed as EnrollmentChallengePayload, challengeHash: challenge.challengeHash as string };
}

export function parseEnrollmentProof(input: string, challenge: EnrollmentChallenge, identity: NativeEnrollmentIdentity): NativeEnrollmentProof {
  const wrapper = record(parseJson(input, 32_768));
  exact(wrapper, ["ok", "command", "result", "commandChannelEnabled"], "ENROLLMENT_PROOF_FIELDS_INVALID");
  if (wrapper.ok !== true || wrapper.command !== "sign-enrollment-challenge" || wrapper.commandChannelEnabled !== false) throw new Error("ENROLLMENT_PROOF_BOUNDARY_INVALID");
  const result = record(wrapper.result);
  exact(result, ["schemaVersion", "challengeId", "challengeHash", "certificateFingerprintSha256", "publicKeySpkiBase64", "canonicalPayload", "proofSignatureBase64", "challengeExpiresAt", "identityExpiresAt"], "ENROLLMENT_PROOF_FIELDS_INVALID");
  const proof = {
    schemaVersion: result.schemaVersion,
    challengeId: result.challengeId,
    challengeHash: result.challengeHash,
    certificateFingerprintSha256: result.certificateFingerprintSha256,
    publicKeySpkiBase64: result.publicKeySpkiBase64,
    canonicalPayload: result.canonicalPayload,
    proofSignatureBase64: result.proofSignatureBase64,
    challengeExpiresAt: result.challengeExpiresAt,
    identityExpiresAt: result.identityExpiresAt
  };
  if (proof.schemaVersion !== 1 || proof.challengeId !== challenge.id || proof.challengeHash !== challenge.challengeHash || proof.certificateFingerprintSha256 !== identity.certificateFingerprintSha256 || proof.publicKeySpkiBase64 !== identity.publicKeySpkiBase64 || proof.canonicalPayload !== stableJson(challenge.payload) || proof.challengeExpiresAt !== challenge.payload.challengeExpiresAt || proof.identityExpiresAt !== challenge.payload.identityExpiresAt) {
    throw new Error("ENROLLMENT_PROOF_BINDING_INVALID");
  }
  text(proof.proofSignatureBase64, BASE64, "ENROLLMENT_SIGNATURE_INVALID");
  if ((proof.proofSignatureBase64 as string).length < 40 || (proof.proofSignatureBase64 as string).length > 2_048) throw new Error("ENROLLMENT_SIGNATURE_INVALID");
  return proof as NativeEnrollmentProof;
}

export function validateRegisteredEnrollmentKey(value: unknown, challenge: EnrollmentChallenge, identity: NativeEnrollmentIdentity): RegisteredEnrollmentKey {
  const key = record(value);
  exact(key, ["algorithm", "publicKeyFormat", "certificateFingerprintSha256", "endpointId", "enrollmentChallengeId", "registeredAt"], "ENROLLMENT_REGISTERED_KEY_FIELDS_INVALID");
  if (key.algorithm !== identity.algorithm || key.publicKeyFormat !== identity.publicKeyFormat || key.certificateFingerprintSha256 !== identity.certificateFingerprintSha256 || key.endpointId !== challenge.payload.endpointId || key.enrollmentChallengeId !== challenge.id) {
    throw new Error("ENROLLMENT_REGISTERED_KEY_BINDING_INVALID");
  }
  text(key.registeredAt, UTC_MILLISECONDS, "ENROLLMENT_TIME_INVALID");
  return key as unknown as RegisteredEnrollmentKey;
}

export function validateApprovedEndpointIdentity(value: unknown, challenge: EnrollmentChallenge): ApprovedEndpointIdentity {
  const endpoint = record(value);
  exact(endpoint, ["endpointId", "connectorId", "missionId", "certificateFingerprintSha256", "enrollmentChallengeId", "status", "issuedAt", "expiresAt", "approvedBy", "revokedAt", "revokedBy", "revocationReason", "currentBootId", "lastSequence", "lastBatchHash", "lastReceiptHash", "lastSeenAt"], "ENROLLMENT_ENDPOINT_FIELDS_INVALID");
  if (endpoint.endpointId !== challenge.payload.endpointId || endpoint.connectorId !== challenge.payload.connectorId || endpoint.missionId !== challenge.payload.missionId || endpoint.certificateFingerprintSha256 !== challenge.payload.certificateFingerprintSha256 || endpoint.enrollmentChallengeId !== challenge.id || endpoint.status !== "active" || endpoint.expiresAt !== challenge.payload.identityExpiresAt || typeof endpoint.approvedBy !== "string" || endpoint.approvedBy.trim().length < 2 || endpoint.approvedBy.length > 120 || endpoint.revokedAt !== null || endpoint.revokedBy !== null || endpoint.revocationReason !== null || endpoint.currentBootId !== null || endpoint.lastSequence !== null || endpoint.lastBatchHash !== null || endpoint.lastReceiptHash !== null || endpoint.lastSeenAt !== null) {
    throw new Error("ENROLLMENT_ENDPOINT_BINDING_INVALID");
  }
  text(endpoint.issuedAt, UTC_MILLISECONDS, "ENROLLMENT_TIME_INVALID");
  return endpoint as unknown as ApprovedEndpointIdentity;
}

export function parseSignedCapabilityReport(input: string, endpoint: ApprovedEndpointIdentity): SignedCapabilityReport {
  const report = record(parseJson(input, 32_768));
  exact(report, ["schemaVersion", "missionId", "connectorId", "endpointId", "certificateFingerprintSha256", "provider", "channel", "eventFamily", "fields", "filterHash", "collectorVersion", "loss", "continuity", "continuousSince", "lastSuccessfulReadAt", "observedAt", "freshnessSeconds", "reportHash", "signatureBase64"], "CAPABILITY_REPORT_FIELDS_INVALID");
  const loss = record(report.loss);
  exact(loss, ["state", "lostRecordCount"], "CAPABILITY_REPORT_LOSS_FIELDS_INVALID");
  if (report.schemaVersion !== 1 || report.missionId !== endpoint.missionId || report.connectorId !== endpoint.connectorId || report.endpointId !== endpoint.endpointId || report.certificateFingerprintSha256 !== endpoint.certificateFingerprintSha256 || report.provider !== "windows-scm" || report.channel !== "system" || report.eventFamily !== "service-change" || !Array.isArray(report.fields) || report.fields.length !== SCM_FIELDS.length || report.fields.some((field, index) => field !== SCM_FIELDS[index]) || report.filterHash !== SCM_FILTER_HASH || report.collectorVersion !== SCM_COLLECTOR_VERSION || loss.state !== "unknown" || loss.lostRecordCount !== null || report.continuity !== "unknown" || report.freshnessSeconds !== 300) {
    throw new Error("CAPABILITY_REPORT_BINDING_INVALID");
  }
  const continuousSince = text(report.continuousSince, UTC_MILLISECONDS, "CAPABILITY_REPORT_TIME_INVALID");
  const lastSuccessfulReadAt = text(report.lastSuccessfulReadAt, UTC_MILLISECONDS, "CAPABILITY_REPORT_TIME_INVALID");
  const observedAt = text(report.observedAt, UTC_MILLISECONDS, "CAPABILITY_REPORT_TIME_INVALID");
  if (Date.parse(continuousSince) > Date.parse(lastSuccessfulReadAt) || Date.parse(lastSuccessfulReadAt) > Date.parse(observedAt) || Date.parse(observedAt) > Date.now() + 30_000) throw new Error("CAPABILITY_REPORT_TIME_INVALID");
  text(report.reportHash, FINGERPRINT, "CAPABILITY_REPORT_HASH_INVALID");
  const signature = text(report.signatureBase64, BASE64, "CAPABILITY_REPORT_SIGNATURE_INVALID");
  if (signature.length < 80 || signature.length > 128) throw new Error("CAPABILITY_REPORT_SIGNATURE_INVALID");
  return report as unknown as SignedCapabilityReport;
}

export async function validateCapabilityReportHash(report: SignedCapabilityReport): Promise<void> {
  const reportHash = report.reportHash;
  const core = Object.fromEntries(
    Object.entries(report).filter(([key]) => key !== "reportHash" && key !== "signatureBase64")
  );
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stableJson(core)));
  const actual = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  if (actual !== reportHash) throw new Error("CAPABILITY_REPORT_HASH_INVALID");
}

export function validateAcceptedCapability(value: unknown, report: SignedCapabilityReport): AcceptedCapability {
  const capability = record(value);
  exact(capability, ["id", "reportHash", "missionId", "connectorId", "endpointId", "certificateFingerprintSha256", "provider", "channel", "eventFamily", "fields", "fieldsHash", "filterHash", "collectorVersion", "loss", "continuity", "continuousSince", "lastSuccessfulReadAt", "observedAt", "freshUntil", "evidenceArtifactId", "recordedAt", "health", "limitation"], "CAPABILITY_RESPONSE_FIELDS_INVALID");
  if (typeof capability.id !== "string" || !/^capability-[a-f0-9-]{36}$/.test(capability.id) || capability.reportHash !== report.reportHash || capability.missionId !== report.missionId || capability.connectorId !== report.connectorId || capability.endpointId !== report.endpointId || capability.certificateFingerprintSha256 !== report.certificateFingerprintSha256 || capability.provider !== report.provider || capability.channel !== report.channel || capability.eventFamily !== report.eventFamily || stableJson(capability.fields) !== stableJson(report.fields) || capability.filterHash !== report.filterHash || capability.collectorVersion !== report.collectorVersion || stableJson(capability.loss) !== stableJson(report.loss) || capability.continuity !== report.continuity || capability.continuousSince !== report.continuousSince || capability.lastSuccessfulReadAt !== report.lastSuccessfulReadAt || capability.observedAt !== report.observedAt || capability.health !== "degraded") {
    throw new Error("CAPABILITY_RESPONSE_BINDING_INVALID");
  }
  text(capability.fieldsHash, FINGERPRINT, "CAPABILITY_RESPONSE_HASH_INVALID");
  const freshUntil = text(capability.freshUntil, UTC_MILLISECONDS, "CAPABILITY_REPORT_TIME_INVALID");
  if (Date.parse(freshUntil) !== Date.parse(report.lastSuccessfulReadAt) + report.freshnessSeconds * 1_000) throw new Error("CAPABILITY_RESPONSE_BINDING_INVALID");
  text(capability.evidenceArtifactId, UUID, "CAPABILITY_EVIDENCE_INVALID");
  text(capability.recordedAt, UTC_MILLISECONDS, "CAPABILITY_REPORT_TIME_INVALID");
  if (typeof capability.limitation !== "string" || capability.limitation.length < 20) throw new Error("CAPABILITY_RESPONSE_BINDING_INVALID");
  return capability as unknown as AcceptedCapability;
}
