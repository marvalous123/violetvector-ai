import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { canonicalHash, stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";

const fingerprintSchema = z.string().regex(/^[a-f0-9]{64}$/);
const signatureSchema = z.string().min(40).max(2_048).regex(/^[A-Za-z0-9+/=]+$/);
const challengeIdSchema = z.string().regex(/^enrollment-[a-f0-9-]{36}$/);
const endpointIdSchema = z.string().regex(/^endpoint-[a-f0-9-]{36}$/);
const renewalIdSchema = z.string().regex(/^renewal-[a-f0-9-]{36}$/);

const enrollmentRequestSchema = z.object({
  missionId: z.string().min(1).max(128),
  certificateFingerprintSha256: fingerprintSchema,
  identityExpiresAt: z.string().datetime({ offset: true })
}).strict();

const enrollmentApprovalSchema = z.object({
  challengeId: challengeIdSchema,
  confirmedCertificateFingerprintSha256: fingerprintSchema,
  proofSignatureBase64: signatureSchema
}).strict();

const enrollmentChallengePayloadSchema = z.object({
  schemaVersion: z.literal(1),
  challengeId: challengeIdSchema,
  missionId: z.string().min(1).max(128),
  connectorId: z.string().regex(/^connector-[a-f0-9-]{36}$/),
  endpointId: endpointIdSchema,
  certificateFingerprintSha256: fingerprintSchema,
  nonceBase64Url: z.string().regex(/^[A-Za-z0-9_-]{40,64}$/),
  requestedAt: z.string().datetime({ offset: true }),
  challengeExpiresAt: z.string().datetime({ offset: true }),
  identityExpiresAt: z.string().datetime({ offset: true })
}).strict();

export type EnrollmentChallengePayload = z.infer<typeof enrollmentChallengePayloadSchema>;

export interface EnrollmentChallenge {
  readonly id: string;
  readonly status: "pending" | "approved" | "expired";
  readonly payload: EnrollmentChallengePayload;
  readonly challengeHash: string;
}

export interface EndpointIdentity {
  readonly endpointId: string;
  readonly connectorId: string;
  readonly missionId: string;
  readonly certificateFingerprintSha256: string;
  readonly enrollmentChallengeId: string;
  readonly status: "active" | "revoked" | "expired";
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly approvedBy: string;
  readonly revokedAt: string | null;
  readonly revokedBy: string | null;
  readonly revocationReason: string | null;
  readonly currentBootId: string | null;
  readonly lastSequence: number | null;
  readonly lastBatchHash: string | null;
  readonly lastReceiptHash: string | null;
  readonly lastSeenAt: string | null;
}

export interface EndpointIdentityRenewal {
  readonly id: string;
  readonly missionId: string;
  readonly previousEndpointId: string;
  readonly replacementEnrollmentChallengeId: string;
  readonly replacementEndpointId: string;
  readonly previousCertificateFingerprintSha256: string;
  readonly replacementCertificateFingerprintSha256: string;
  readonly status: "pending" | "activated" | "expired";
  readonly reason: string;
  readonly requestedBy: string;
  readonly requestedAt: string;
  readonly challengeExpiresAt: string;
  readonly activatedBy: string | null;
  readonly activatedAt: string | null;
}

export interface EndpointBatchBinding {
  readonly missionId: string;
  readonly connectorId: string;
  readonly endpointId: string;
  readonly certificateFingerprintSha256: string;
}

interface ChallengeRow {
  id: string;
  mission_id: string;
  connector_id: string;
  endpoint_id: string;
  certificate_fingerprint_sha256: string;
  challenge_json: string;
  challenge_hash: string;
  status: "pending" | "approved" | "expired";
  requested_by: string;
  requested_at: string;
  expires_at: string;
  identity_expires_at: string;
  approved_by: string | null;
  approved_at: string | null;
}

export interface EndpointIdentityRow {
  endpoint_id: string;
  connector_id: string;
  mission_id: string;
  certificate_fingerprint_sha256: string;
  enrollment_challenge_id: string;
  status: "active" | "revoked" | "expired";
  issued_at: string;
  expires_at: string;
  approved_by: string;
  revoked_at: string | null;
  revoked_by: string | null;
  revocation_reason: string | null;
  current_boot_id: string | null;
  last_sequence: number | null;
  last_batch_hash: string | null;
  last_receipt_hash: string | null;
  last_seen_at: string | null;
}

interface RenewalRow {
  id: string;
  mission_id: string;
  previous_endpoint_id: string;
  replacement_enrollment_challenge_id: string;
  replacement_endpoint_id: string;
  previous_certificate_fingerprint_sha256: string;
  replacement_certificate_fingerprint_sha256: string;
  status: "pending" | "activated" | "expired";
  reason: string;
  requested_by: string;
  requested_at: string;
  challenge_expires_at: string;
  activated_by: string | null;
  activated_at: string | null;
}

export type EnrollmentProofVerifier = (
  payload: string,
  signatureBase64: string,
  certificateFingerprintSha256: string
) => boolean;

export interface EndpointRegistryOptions {
  readonly challengeTtlMs?: number;
  readonly maxIdentityTtlMs?: number;
}

function cleanOperator(operator: string): string {
  const value = operator.trim();
  if (value.length < 2 || value.length > 120) throw new Error("OPERATOR_INVALID");
  return value;
}

function cleanReason(reason: string): string {
  const value = reason.trim();
  if (value.length < 5 || value.length > 500) throw new Error("ENDPOINT_REVOCATION_REASON_INVALID");
  return value;
}

function cleanRenewalReason(reason: string): string {
  const value = reason.trim();
  if (value.length < 10 || value.length > 500) throw new Error("ENDPOINT_RENEWAL_REASON_INVALID");
  return value;
}

export class EndpointRegistryService {
  readonly #challengeTtlMs: number;
  readonly #maxIdentityTtlMs: number;

  constructor(
    private readonly database: DatabaseSync,
    private readonly audit: AuditService,
    private readonly verifyEnrollmentProof: EnrollmentProofVerifier,
    options: EndpointRegistryOptions = {}
  ) {
    this.#challengeTtlMs = options.challengeTtlMs ?? 5 * 60_000;
    this.#maxIdentityTtlMs = options.maxIdentityTtlMs ?? 7 * 24 * 60 * 60_000;
    if (
      this.#challengeTtlMs < 30_000 ||
      this.#challengeTtlMs > 15 * 60_000 ||
      this.#maxIdentityTtlMs < this.#challengeTtlMs ||
      this.#maxIdentityTtlMs > 30 * 24 * 60 * 60_000
    ) {
      throw new Error("ENDPOINT_REGISTRY_TTL_INVALID");
    }
  }

  requestEnrollment(
    input: {
      missionId: string;
      certificateFingerprintSha256: string;
      identityExpiresAt: string;
    },
    requestedBy: string,
    now = new Date()
  ): EnrollmentChallenge {
    const parsed = enrollmentRequestSchema.parse(input);
    const operator = cleanOperator(requestedBy);
    if (!this.database.prepare("SELECT id FROM missions WHERE id = ?").get(parsed.missionId)) {
      throw new Error("MISSION_NOT_FOUND");
    }
    const identityExpiresAt = new Date(parsed.identityExpiresAt);
    const challengeExpiresAt = new Date(now.valueOf() + this.#challengeTtlMs);
    if (
      identityExpiresAt.valueOf() <= challengeExpiresAt.valueOf() ||
      identityExpiresAt.valueOf() > now.valueOf() + this.#maxIdentityTtlMs
    ) {
      throw new Error("ENDPOINT_IDENTITY_EXPIRY_INVALID");
    }

    const challengeId = `enrollment-${randomUUID()}`;
    const connectorId = `connector-${randomUUID()}`;
    const endpointId = `endpoint-${randomUUID()}`;
    const payload = enrollmentChallengePayloadSchema.parse({
      schemaVersion: 1,
      challengeId,
      missionId: parsed.missionId,
      connectorId,
      endpointId,
      certificateFingerprintSha256: parsed.certificateFingerprintSha256,
      nonceBase64Url: randomBytes(32).toString("base64url"),
      requestedAt: now.toISOString(),
      challengeExpiresAt: challengeExpiresAt.toISOString(),
      identityExpiresAt: identityExpiresAt.toISOString()
    });
    const challengeJson = stableJson(payload);
    const challengeHash = canonicalHash(payload);

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO endpoint_enrollment_challenges(
             id, mission_id, connector_id, endpoint_id, certificate_fingerprint_sha256,
             challenge_json, challenge_hash, status, requested_by, requested_at,
             expires_at, identity_expires_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`
        )
        .run(
          challengeId,
          parsed.missionId,
          connectorId,
          endpointId,
          parsed.certificateFingerprintSha256,
          challengeJson,
          challengeHash,
          operator,
          now.toISOString(),
          challengeExpiresAt.toISOString(),
          identityExpiresAt.toISOString()
        );
      this.audit.append(
        "endpoint.enrollment.requested",
        {
          challengeId,
          challengeHash,
          missionId: parsed.missionId,
          connectorId,
          endpointId,
          certificateFingerprintSha256: parsed.certificateFingerprintSha256,
          requestedBy: operator,
          challengeExpiresAt: challengeExpiresAt.toISOString(),
          identityExpiresAt: identityExpiresAt.toISOString()
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return { id: challengeId, status: "pending", payload, challengeHash };
  }

  requestRenewal(
    previousEndpointIdInput: string,
    input: {
      certificateFingerprintSha256: string;
      identityExpiresAt: string;
      reason: string;
    },
    requestedBy: string,
    now = new Date()
  ): { renewal: EndpointIdentityRenewal; challenge: EnrollmentChallenge } {
    const previousEndpointId = endpointIdSchema.parse(previousEndpointIdInput);
    const operator = cleanOperator(requestedBy);
    const reason = cleanRenewalReason(input.reason);
    const previous = this.getIdentityRow(previousEndpointId);
    if (previous.status !== "active") throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
    if (now.valueOf() >= new Date(previous.expires_at).valueOf()) {
      this.expireIdentity(previous, now);
      throw new Error("ENDPOINT_IDENTITY_EXPIRED");
    }
    const parsed = enrollmentRequestSchema.parse({
      missionId: previous.mission_id,
      certificateFingerprintSha256: input.certificateFingerprintSha256,
      identityExpiresAt: input.identityExpiresAt
    });
    if (parsed.certificateFingerprintSha256 === previous.certificate_fingerprint_sha256) {
      throw new Error("ENDPOINT_RENEWAL_KEY_REUSE_FORBIDDEN");
    }
    if (
      this.database
        .prepare(
          `SELECT certificate_fingerprint_sha256
           FROM endpoint_public_keys
           WHERE certificate_fingerprint_sha256 = ?
           UNION
           SELECT certificate_fingerprint_sha256
           FROM endpoint_identities
           WHERE certificate_fingerprint_sha256 = ?
           LIMIT 1`
        )
        .get(
          parsed.certificateFingerprintSha256,
          parsed.certificateFingerprintSha256
        )
    ) {
      throw new Error("ENDPOINT_RENEWAL_KEY_REUSE_FORBIDDEN");
    }
    if (
      this.database
        .prepare(
          `SELECT id FROM endpoint_identity_renewals
           WHERE previous_endpoint_id = ? AND status = 'pending'`
        )
        .get(previousEndpointId)
    ) {
      throw new Error("ENDPOINT_RENEWAL_ALREADY_PENDING");
    }
    const identityExpiresAt = new Date(parsed.identityExpiresAt);
    const challengeExpiresAt = new Date(now.valueOf() + this.#challengeTtlMs);
    if (
      identityExpiresAt.valueOf() <= challengeExpiresAt.valueOf() ||
      identityExpiresAt.valueOf() > now.valueOf() + this.#maxIdentityTtlMs
    ) {
      throw new Error("ENDPOINT_IDENTITY_EXPIRY_INVALID");
    }

    const challengeId = `enrollment-${randomUUID()}`;
    const renewalId = `renewal-${randomUUID()}`;
    const connectorId = `connector-${randomUUID()}`;
    const endpointId = `endpoint-${randomUUID()}`;
    const payload = enrollmentChallengePayloadSchema.parse({
      schemaVersion: 1,
      challengeId,
      missionId: previous.mission_id,
      connectorId,
      endpointId,
      certificateFingerprintSha256: parsed.certificateFingerprintSha256,
      nonceBase64Url: randomBytes(32).toString("base64url"),
      requestedAt: now.toISOString(),
      challengeExpiresAt: challengeExpiresAt.toISOString(),
      identityExpiresAt: identityExpiresAt.toISOString()
    });
    const challengeJson = stableJson(payload);
    const challengeHash = canonicalHash(payload);

    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `INSERT INTO endpoint_enrollment_challenges(
             id, mission_id, connector_id, endpoint_id, certificate_fingerprint_sha256,
             challenge_json, challenge_hash, status, requested_by, requested_at,
             expires_at, identity_expires_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`
        )
        .run(
          challengeId,
          previous.mission_id,
          connectorId,
          endpointId,
          parsed.certificateFingerprintSha256,
          challengeJson,
          challengeHash,
          operator,
          now.toISOString(),
          challengeExpiresAt.toISOString(),
          identityExpiresAt.toISOString()
        );
      this.database
        .prepare(
          `INSERT INTO endpoint_identity_renewals(
             id, mission_id, previous_endpoint_id,
             replacement_enrollment_challenge_id, replacement_endpoint_id,
             previous_certificate_fingerprint_sha256,
             replacement_certificate_fingerprint_sha256, status, reason,
             requested_by, requested_at, challenge_expires_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`
        )
        .run(
          renewalId,
          previous.mission_id,
          previousEndpointId,
          challengeId,
          endpointId,
          previous.certificate_fingerprint_sha256,
          parsed.certificateFingerprintSha256,
          reason,
          operator,
          now.toISOString(),
          challengeExpiresAt.toISOString()
        );
      this.audit.append(
        "endpoint.renewal.requested",
        {
          renewalId,
          missionId: previous.mission_id,
          previousEndpointId,
          previousCertificateFingerprintSha256:
            previous.certificate_fingerprint_sha256,
          replacementChallengeId: challengeId,
          replacementChallengeHash: challengeHash,
          replacementEndpointId: endpointId,
          replacementCertificateFingerprintSha256:
            parsed.certificateFingerprintSha256,
          requestedBy: operator,
          reason,
          challengeExpiresAt: challengeExpiresAt.toISOString(),
          identityExpiresAt: identityExpiresAt.toISOString()
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return {
      renewal: this.getRenewal(renewalId),
      challenge: { id: challengeId, status: "pending", payload, challengeHash }
    };
  }

  approveEnrollment(
    input: {
      challengeId: string;
      confirmedCertificateFingerprintSha256: string;
      proofSignatureBase64: string;
    },
    approvedBy: string,
    now = new Date()
  ): EndpointIdentity {
    const parsed = enrollmentApprovalSchema.parse(input);
    const operator = cleanOperator(approvedBy);
    const challenge = this.getChallengeRow(parsed.challengeId);
    if (challenge.status !== "pending") throw new Error("ENDPOINT_ENROLLMENT_NOT_PENDING");
    if (challenge.certificate_fingerprint_sha256 !== parsed.confirmedCertificateFingerprintSha256) {
      throw new Error("ENDPOINT_CERTIFICATE_MISMATCH");
    }
    if (now.valueOf() >= new Date(challenge.expires_at).valueOf()) {
      this.expireChallenge(challenge, now);
      throw new Error("ENDPOINT_ENROLLMENT_EXPIRED");
    }
    if (now.valueOf() >= new Date(challenge.identity_expires_at).valueOf()) {
      throw new Error("ENDPOINT_IDENTITY_EXPIRY_INVALID");
    }
    const payload = enrollmentChallengePayloadSchema.parse(JSON.parse(challenge.challenge_json));
    if (canonicalHash(payload) !== challenge.challenge_hash) {
      throw new Error("ENDPOINT_ENROLLMENT_CHALLENGE_INVALID");
    }
    const proofValid = (() => {
      try {
        return this.verifyEnrollmentProof(
          stableJson(payload),
          parsed.proofSignatureBase64,
          challenge.certificate_fingerprint_sha256
        );
      } catch {
        return false;
      }
    })();
    if (!proofValid) throw new Error("ENDPOINT_ENROLLMENT_PROOF_INVALID");

    this.database.exec("BEGIN IMMEDIATE");
    try {
      const changed = this.database
        .prepare(
          `UPDATE endpoint_enrollment_challenges
           SET status = 'approved', approved_by = ?, approved_at = ?
           WHERE id = ? AND status = 'pending'`
        )
        .run(operator, now.toISOString(), challenge.id);
      if (Number(changed.changes) !== 1) throw new Error("ENDPOINT_ENROLLMENT_NOT_PENDING");
      this.database
        .prepare(
          `INSERT INTO endpoint_identities(
             endpoint_id, connector_id, mission_id, certificate_fingerprint_sha256,
             enrollment_challenge_id, status, issued_at, expires_at, approved_by
           ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
        )
        .run(
          challenge.endpoint_id,
          challenge.connector_id,
          challenge.mission_id,
          challenge.certificate_fingerprint_sha256,
          challenge.id,
          now.toISOString(),
          challenge.identity_expires_at,
          operator
        );
      this.audit.append(
        "endpoint.enrollment.approved",
        {
          challengeId: challenge.id,
          challengeHash: challenge.challenge_hash,
          missionId: challenge.mission_id,
          connectorId: challenge.connector_id,
          endpointId: challenge.endpoint_id,
          certificateFingerprintSha256: challenge.certificate_fingerprint_sha256,
          approvedBy: operator,
          expiresAt: challenge.identity_expires_at
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.getIdentity(challenge.endpoint_id);
  }

  approveRenewal(
    input: {
      challengeId: string;
      confirmedCertificateFingerprintSha256: string;
      proofSignatureBase64: string;
    },
    approvedBy: string,
    now = new Date()
  ): {
    renewal: EndpointIdentityRenewal;
    previousIdentity: EndpointIdentity;
    replacementIdentity: EndpointIdentity;
  } {
    const parsed = enrollmentApprovalSchema.parse(input);
    const operator = cleanOperator(approvedBy);
    const challenge = this.getChallengeRow(parsed.challengeId);
    const renewal = this.database
      .prepare(
        `SELECT * FROM endpoint_identity_renewals
         WHERE replacement_enrollment_challenge_id = ?`
      )
      .get(challenge.id) as unknown as RenewalRow | undefined;
    if (!renewal) throw new Error("ENDPOINT_RENEWAL_NOT_FOUND");
    if (renewal.status !== "pending") throw new Error("ENDPOINT_RENEWAL_NOT_PENDING");
    if (challenge.status !== "pending") throw new Error("ENDPOINT_ENROLLMENT_NOT_PENDING");
    if (
      challenge.certificate_fingerprint_sha256 !==
        parsed.confirmedCertificateFingerprintSha256 ||
      renewal.replacement_certificate_fingerprint_sha256 !==
        parsed.confirmedCertificateFingerprintSha256
    ) {
      throw new Error("ENDPOINT_CERTIFICATE_MISMATCH");
    }
    if (now.valueOf() >= new Date(challenge.expires_at).valueOf()) {
      this.expireChallenge(challenge, now);
      throw new Error("ENDPOINT_ENROLLMENT_EXPIRED");
    }
    if (now.valueOf() >= new Date(challenge.identity_expires_at).valueOf()) {
      throw new Error("ENDPOINT_IDENTITY_EXPIRY_INVALID");
    }
    const previous = this.getIdentityRow(renewal.previous_endpoint_id);
    if (previous.status !== "active") throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
    if (now.valueOf() >= new Date(previous.expires_at).valueOf()) {
      this.expireIdentity(previous, now);
      throw new Error("ENDPOINT_IDENTITY_EXPIRED");
    }
    if (
      previous.mission_id !== challenge.mission_id ||
      previous.mission_id !== renewal.mission_id ||
      previous.certificate_fingerprint_sha256 !==
        renewal.previous_certificate_fingerprint_sha256 ||
      challenge.endpoint_id !== renewal.replacement_endpoint_id
    ) {
      throw new Error("ENDPOINT_RENEWAL_BINDING_INVALID");
    }
    const payload = enrollmentChallengePayloadSchema.parse(
      JSON.parse(challenge.challenge_json)
    );
    if (canonicalHash(payload) !== challenge.challenge_hash) {
      throw new Error("ENDPOINT_ENROLLMENT_CHALLENGE_INVALID");
    }
    const proofValid = (() => {
      try {
        return this.verifyEnrollmentProof(
          stableJson(payload),
          parsed.proofSignatureBase64,
          challenge.certificate_fingerprint_sha256
        );
      } catch {
        return false;
      }
    })();
    if (!proofValid) throw new Error("ENDPOINT_ENROLLMENT_PROOF_INVALID");

    const revokedReason = `Replaced by approved endpoint renewal ${renewal.id}.`;
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const challengeChanged = this.database
        .prepare(
          `UPDATE endpoint_enrollment_challenges
           SET status = 'approved', approved_by = ?, approved_at = ?
           WHERE id = ? AND status = 'pending'`
        )
        .run(operator, now.toISOString(), challenge.id);
      if (Number(challengeChanged.changes) !== 1) {
        throw new Error("ENDPOINT_ENROLLMENT_NOT_PENDING");
      }
      this.database
        .prepare(
          `INSERT INTO endpoint_identities(
             endpoint_id, connector_id, mission_id, certificate_fingerprint_sha256,
             enrollment_challenge_id, status, issued_at, expires_at, approved_by
           ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
        )
        .run(
          challenge.endpoint_id,
          challenge.connector_id,
          challenge.mission_id,
          challenge.certificate_fingerprint_sha256,
          challenge.id,
          now.toISOString(),
          challenge.identity_expires_at,
          operator
        );
      const previousChanged = this.database
        .prepare(
          `UPDATE endpoint_identities
           SET status = 'revoked', revoked_at = ?, revoked_by = ?,
               revocation_reason = ?
           WHERE endpoint_id = ? AND status = 'active'`
        )
        .run(
          now.toISOString(),
          operator,
          revokedReason,
          previous.endpoint_id
        );
      if (Number(previousChanged.changes) !== 1) {
        throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
      }
      const renewalChanged = this.database
        .prepare(
          `UPDATE endpoint_identity_renewals
           SET status = 'activated', activated_by = ?, activated_at = ?
           WHERE id = ? AND status = 'pending'`
        )
        .run(operator, now.toISOString(), renewal.id);
      if (Number(renewalChanged.changes) !== 1) {
        throw new Error("ENDPOINT_RENEWAL_NOT_PENDING");
      }
      this.audit.append(
        "endpoint.renewal.activated",
        {
          renewalId: renewal.id,
          missionId: renewal.mission_id,
          previousEndpointId: previous.endpoint_id,
          replacementChallengeId: challenge.id,
          replacementEndpointId: challenge.endpoint_id,
          previousCertificateFingerprintSha256:
            previous.certificate_fingerprint_sha256,
          replacementCertificateFingerprintSha256:
            challenge.certificate_fingerprint_sha256,
          activatedBy: operator,
          previousIdentityRevoked: true
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return {
      renewal: this.getRenewal(renewal.id),
      previousIdentity: this.getIdentity(previous.endpoint_id),
      replacementIdentity: this.getIdentity(challenge.endpoint_id)
    };
  }

  revokeEndpoint(endpointIdInput: string, revokedBy: string, reason: string, now = new Date()): EndpointIdentity {
    const endpointId = endpointIdSchema.parse(endpointIdInput);
    const operator = cleanOperator(revokedBy);
    const cleanRevocationReason = cleanReason(reason);
    const identity = this.getIdentityRow(endpointId);
    if (identity.status !== "active") throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const changed = this.database
        .prepare(
          `UPDATE endpoint_identities
           SET status = 'revoked', revoked_at = ?, revoked_by = ?, revocation_reason = ?
           WHERE endpoint_id = ? AND status = 'active'`
        )
        .run(now.toISOString(), operator, cleanRevocationReason, endpointId);
      if (Number(changed.changes) !== 1) throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
      this.audit.append(
        "endpoint.identity.revoked",
        {
          missionId: identity.mission_id,
          connectorId: identity.connector_id,
          endpointId,
          revokedBy: operator,
          reason: cleanRevocationReason
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return this.getIdentity(endpointId);
  }

  authenticateBatch(binding: EndpointBatchBinding, now = new Date()): EndpointIdentityRow {
    const fingerprint = fingerprintSchema.parse(binding.certificateFingerprintSha256);
    const row = this.database
      .prepare("SELECT * FROM endpoint_identities WHERE connector_id = ?")
      .get(binding.connectorId) as unknown as EndpointIdentityRow | undefined;
    if (!row) throw new Error("ENDPOINT_IDENTITY_NOT_FOUND");
    if (
      row.endpoint_id !== binding.endpointId ||
      row.mission_id !== binding.missionId ||
      row.certificate_fingerprint_sha256 !== fingerprint
    ) {
      throw new Error("ENDPOINT_IDENTITY_BINDING_MISMATCH");
    }
    if (row.status !== "active") throw new Error("ENDPOINT_IDENTITY_NOT_ACTIVE");
    if (now.valueOf() >= new Date(row.expires_at).valueOf()) {
      this.expireIdentity(row, now);
      throw new Error("ENDPOINT_IDENTITY_EXPIRED");
    }
    return this.getIdentityRow(row.endpoint_id);
  }

  getIdentity(endpointIdInput: string): EndpointIdentity {
    const row = this.getIdentityRow(endpointIdSchema.parse(endpointIdInput));
    return {
      endpointId: row.endpoint_id,
      connectorId: row.connector_id,
      missionId: row.mission_id,
      certificateFingerprintSha256: row.certificate_fingerprint_sha256,
      enrollmentChallengeId: row.enrollment_challenge_id,
      status: row.status,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      approvedBy: row.approved_by,
      revokedAt: row.revoked_at,
      revokedBy: row.revoked_by,
      revocationReason: row.revocation_reason,
      currentBootId: row.current_boot_id,
      lastSequence: row.last_sequence,
      lastBatchHash: row.last_batch_hash,
      lastReceiptHash: row.last_receipt_hash,
      lastSeenAt: row.last_seen_at
    };
  }

  getRenewal(renewalIdInput: string): EndpointIdentityRenewal {
    const renewalId = renewalIdSchema.parse(renewalIdInput);
    const row = this.database
      .prepare("SELECT * FROM endpoint_identity_renewals WHERE id = ?")
      .get(renewalId) as unknown as RenewalRow | undefined;
    if (!row) throw new Error("ENDPOINT_RENEWAL_NOT_FOUND");
    return this.toRenewal(row);
  }

  listRenewals(missionIdInput?: string): EndpointIdentityRenewal[] {
    const missionId = missionIdInput?.trim();
    if (missionId !== undefined && (missionId.length < 1 || missionId.length > 128)) {
      throw new Error("MISSION_ID_INVALID");
    }
    const rows = missionId
      ? this.database
          .prepare(
            `SELECT * FROM endpoint_identity_renewals
             WHERE mission_id = ? ORDER BY requested_at DESC, id DESC LIMIT 200`
          )
          .all(missionId)
      : this.database
          .prepare(
            `SELECT * FROM endpoint_identity_renewals
             ORDER BY requested_at DESC, id DESC LIMIT 200`
          )
          .all();
    return (rows as unknown as RenewalRow[]).map((row) => this.toRenewal(row));
  }

  private toRenewal(row: RenewalRow): EndpointIdentityRenewal {
    return {
      id: row.id,
      missionId: row.mission_id,
      previousEndpointId: row.previous_endpoint_id,
      replacementEnrollmentChallengeId:
        row.replacement_enrollment_challenge_id,
      replacementEndpointId: row.replacement_endpoint_id,
      previousCertificateFingerprintSha256:
        row.previous_certificate_fingerprint_sha256,
      replacementCertificateFingerprintSha256:
        row.replacement_certificate_fingerprint_sha256,
      status: row.status,
      reason: row.reason,
      requestedBy: row.requested_by,
      requestedAt: row.requested_at,
      challengeExpiresAt: row.challenge_expires_at,
      activatedBy: row.activated_by,
      activatedAt: row.activated_at
    };
  }

  private getChallengeRow(challengeId: string): ChallengeRow {
    const row = this.database
      .prepare("SELECT * FROM endpoint_enrollment_challenges WHERE id = ?")
      .get(challengeId) as unknown as ChallengeRow | undefined;
    if (!row) throw new Error("ENDPOINT_ENROLLMENT_NOT_FOUND");
    return row;
  }

  private getIdentityRow(endpointId: string): EndpointIdentityRow {
    const row = this.database
      .prepare("SELECT * FROM endpoint_identities WHERE endpoint_id = ?")
      .get(endpointId) as unknown as EndpointIdentityRow | undefined;
    if (!row) throw new Error("ENDPOINT_IDENTITY_NOT_FOUND");
    return row;
  }

  private expireChallenge(challenge: ChallengeRow, now: Date): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          "UPDATE endpoint_enrollment_challenges SET status = 'expired' WHERE id = ? AND status = 'pending'"
        )
        .run(challenge.id);
      const renewalExpired = this.database
        .prepare(
          `UPDATE endpoint_identity_renewals
           SET status = 'expired'
           WHERE replacement_enrollment_challenge_id = ?
             AND status = 'pending'`
        )
        .run(challenge.id);
      this.audit.append(
        "endpoint.enrollment.expired",
        {
          challengeId: challenge.id,
          challengeHash: challenge.challenge_hash,
          missionId: challenge.mission_id,
          connectorId: challenge.connector_id,
          endpointId: challenge.endpoint_id
        },
        now
      );
      if (Number(renewalExpired.changes) === 1) {
        const renewal = this.database
          .prepare(
            `SELECT id, mission_id, previous_endpoint_id, replacement_endpoint_id
             FROM endpoint_identity_renewals
             WHERE replacement_enrollment_challenge_id = ?`
          )
          .get(challenge.id) as {
            id: string;
            mission_id: string;
            previous_endpoint_id: string;
            replacement_endpoint_id: string;
          };
        this.audit.append(
          "endpoint.renewal.expired",
          {
            renewalId: renewal.id,
            missionId: renewal.mission_id,
            previousEndpointId: renewal.previous_endpoint_id,
            replacementEndpointId: renewal.replacement_endpoint_id,
            replacementChallengeId: challenge.id
          },
          now
        );
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  private expireIdentity(identity: EndpointIdentityRow, now: Date): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          "UPDATE endpoint_identities SET status = 'expired' WHERE endpoint_id = ? AND status = 'active'"
        )
        .run(identity.endpoint_id);
      this.audit.append(
        "endpoint.identity.expired",
        {
          missionId: identity.mission_id,
          connectorId: identity.connector_id,
          endpointId: identity.endpoint_id,
          expiresAt: identity.expires_at
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }
}
