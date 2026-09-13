import {
  createHash,
  createPublicKey,
  verify,
  type KeyObject
} from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { z } from "zod";
import { stableJson } from "../domain/stable-json.js";
import type { AuditService } from "./audit-service.js";
import type { TelemetrySignatureVerifier } from "./endpoint-ingestion-service.js";
import type { EnrollmentProofVerifier } from "./endpoint-registry-service.js";

const fingerprintSchema = z.string().regex(/^[a-f0-9]{64}$/);
const challengeIdSchema = z.string().regex(/^enrollment-[a-f0-9-]{36}$/);
const endpointIdSchema = z.string().regex(/^endpoint-[a-z0-9-]{8,80}$/);
const connectorIdSchema = z.string().regex(/^connector-[a-z0-9-]{8,80}$/);
const spkiBase64Schema = z.string().min(56).max(4_096).regex(/^[A-Za-z0-9+/=]+$/);
const signatureBase64Schema = z.string().min(80).max(128).regex(/^[A-Za-z0-9+/=]+$/);

const enrollmentPayloadSchema = z.object({
  schemaVersion: z.literal(1),
  challengeId: challengeIdSchema,
  missionId: z.string().min(1).max(128),
  connectorId: connectorIdSchema,
  endpointId: endpointIdSchema,
  certificateFingerprintSha256: fingerprintSchema,
  nonceBase64Url: z.string().regex(/^[A-Za-z0-9_-]{40,64}$/),
  requestedAt: z.string().datetime({ offset: true }),
  challengeExpiresAt: z.string().datetime({ offset: true }),
  identityExpiresAt: z.string().datetime({ offset: true })
}).strict();

const endpointSignedPayloadBindingSchema = z.object({
  schemaVersion: z.literal(1),
  missionId: z.string().min(1).max(128),
  connectorId: connectorIdSchema,
  endpointId: endpointIdSchema,
  certificateFingerprintSha256: fingerprintSchema
}).passthrough();

interface EnrollmentKeyRow {
  certificate_fingerprint_sha256: string;
  endpoint_id: string;
  enrollment_challenge_id: string;
  algorithm: EndpointSignatureAlgorithm;
  public_key_spki_base64: string;
  challenge_json: string;
  challenge_status: "pending" | "approved" | "expired";
}

interface TelemetryKeyRow {
  certificate_fingerprint_sha256: string;
  endpoint_id: string;
  connector_id: string;
  mission_id: string;
  identity_status: "active" | "revoked" | "expired";
  algorithm: EndpointSignatureAlgorithm;
  public_key_spki_base64: string;
}

interface ChallengeBindingRow {
  endpoint_id: string;
  certificate_fingerprint_sha256: string;
  status: "pending" | "approved" | "expired";
  expires_at: string;
}

interface ExistingPublicKeyRow {
  endpoint_id: string;
  enrollment_challenge_id: string;
  algorithm: EndpointSignatureAlgorithm;
  public_key_format: "spki-der";
  public_key_spki_base64: string;
  challenge_status: "pending" | "approved" | "expired";
  identity_count: number;
}

export interface RegisteredEndpointPublicKey {
  readonly algorithm: EndpointSignatureAlgorithm;
  readonly publicKeyFormat: "spki-der";
  readonly certificateFingerprintSha256: string;
  readonly endpointId: string;
  readonly enrollmentChallengeId: string;
  readonly registeredAt: string;
}

export type EndpointSignatureAlgorithm =
  | "ed25519"
  | "ecdsa-p256-sha256";

export const ENDPOINT_KEY_PROFILES = {
  ed25519: "sha256-spki-der-ed25519",
  "ecdsa-p256-sha256": "sha256-spki-der-ecdsa-p256"
} as const satisfies Record<EndpointSignatureAlgorithm, string>;

function decodeCanonicalBase64(value: string, errorCode: string): Buffer {
  const bytes = Buffer.from(value, "base64");
  if (bytes.length === 0 || bytes.toString("base64") !== value) {
    throw new Error(errorCode);
  }
  return bytes;
}

function importEndpointPublicKey(publicKeySpkiBase64: string): {
  algorithm: EndpointSignatureAlgorithm;
  key: KeyObject;
  spki: Buffer;
  canonicalBase64: string;
  fingerprint: string;
} {
  const candidate = spkiBase64Schema.parse(publicKeySpkiBase64);
  const spki = decodeCanonicalBase64(candidate, "ENDPOINT_PUBLIC_KEY_ENCODING_INVALID");
  let key: KeyObject;
  try {
    key = createPublicKey({ key: spki, format: "der", type: "spki" });
  } catch {
    throw new Error("ENDPOINT_PUBLIC_KEY_INVALID");
  }
  const algorithm =
    key.asymmetricKeyType === "ed25519"
      ? "ed25519"
      : key.asymmetricKeyType === "ec" &&
          ["prime256v1", "P-256"].includes(key.asymmetricKeyDetails?.namedCurve ?? "")
        ? "ecdsa-p256-sha256"
        : undefined;
  if (!algorithm) {
    throw new Error("ENDPOINT_PUBLIC_KEY_ALGORITHM_INVALID");
  }
  const canonicalSpki = key.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(canonicalSpki) || !canonicalSpki.equals(spki)) {
    throw new Error("ENDPOINT_PUBLIC_KEY_ENCODING_INVALID");
  }
  return {
    algorithm,
    key,
    spki,
    canonicalBase64: spki.toString("base64"),
    fingerprint: createHash("sha256").update(spki).digest("hex")
  };
}

function verifyEndpointSignature(
  algorithm: EndpointSignatureAlgorithm,
  payload: string,
  signatureBase64: string,
  publicKeySpkiBase64: string
): boolean {
  try {
    const signature = decodeCanonicalBase64(
      signatureBase64Schema.parse(signatureBase64),
      "ENDPOINT_SIGNATURE_ENCODING_INVALID"
    );
    if (signature.length !== 64) return false;
    const imported = importEndpointPublicKey(publicKeySpkiBase64);
    if (imported.algorithm !== algorithm) return false;
    return algorithm === "ed25519"
      ? verify(null, Buffer.from(payload, "utf8"), imported.key, signature)
      : verify(
          "sha256",
          Buffer.from(payload, "utf8"),
          { key: imported.key, dsaEncoding: "ieee-p1363" },
          signature
        );
  } catch {
    return false;
  }
}

export class EndpointCryptoService {
  constructor(
    private readonly database: DatabaseSync,
    private readonly audit: AuditService
  ) {}

  registerEnrollmentPublicKey(
    input: {
      challengeId: string;
      publicKeySpkiBase64: string;
    },
    now = new Date()
  ): RegisteredEndpointPublicKey {
    const challengeId = challengeIdSchema.parse(input.challengeId);
    const publicKey = importEndpointPublicKey(input.publicKeySpkiBase64);
    const challenge = this.database
      .prepare(
        `SELECT endpoint_id, certificate_fingerprint_sha256, status, expires_at
         FROM endpoint_enrollment_challenges
         WHERE id = ?`
      )
      .get(challengeId) as unknown as ChallengeBindingRow | undefined;
    if (!challenge) throw new Error("ENDPOINT_ENROLLMENT_NOT_FOUND");
    if (challenge.status !== "pending") throw new Error("ENDPOINT_ENROLLMENT_NOT_PENDING");
    if (now.valueOf() >= new Date(challenge.expires_at).valueOf()) {
      throw new Error("ENDPOINT_ENROLLMENT_EXPIRED");
    }
    if (challenge.certificate_fingerprint_sha256 !== publicKey.fingerprint) {
      throw new Error("ENDPOINT_PUBLIC_KEY_FINGERPRINT_MISMATCH");
    }

    const existing = this.database
      .prepare(
        `SELECT key.endpoint_id, key.enrollment_challenge_id, key.algorithm,
                key.public_key_format, key.public_key_spki_base64,
                previous.status AS challenge_status,
                (SELECT COUNT(*) FROM endpoint_identities identity
                 WHERE identity.certificate_fingerprint_sha256 =
                       key.certificate_fingerprint_sha256) AS identity_count
         FROM endpoint_public_keys key
         JOIN endpoint_enrollment_challenges previous
           ON previous.id = key.enrollment_challenge_id
         WHERE key.certificate_fingerprint_sha256 = ?`
      )
      .get(publicKey.fingerprint) as unknown as ExistingPublicKeyRow | undefined;
    if (
      existing &&
      (
        existing.algorithm !== publicKey.algorithm ||
        existing.public_key_format !== "spki-der" ||
        existing.public_key_spki_base64 !== publicKey.canonicalBase64
      )
    ) {
      throw new Error("ENDPOINT_PUBLIC_KEY_MATERIAL_MISMATCH");
    }
    if (
      existing &&
      (existing.challenge_status !== "expired" || existing.identity_count !== 0)
    ) {
      throw new Error("ENDPOINT_PUBLIC_KEY_REBIND_INVALID");
    }

    this.database.exec("BEGIN IMMEDIATE");
    try {
      if (existing) {
        const rebound = this.database
          .prepare(
            `UPDATE endpoint_public_keys
             SET endpoint_id = ?, enrollment_challenge_id = ?, registered_at = ?
             WHERE certificate_fingerprint_sha256 = ?`
          )
          .run(
            challenge.endpoint_id,
            challengeId,
            now.toISOString(),
            publicKey.fingerprint
          );
        if (Number(rebound.changes) !== 1) {
          throw new Error("ENDPOINT_PUBLIC_KEY_REBIND_INVALID");
        }
      } else {
        this.database
          .prepare(
            `INSERT INTO endpoint_public_keys(
               certificate_fingerprint_sha256, endpoint_id, enrollment_challenge_id,
               algorithm, public_key_format, public_key_spki_base64, registered_at
             ) VALUES (?, ?, ?, ?, 'spki-der', ?, ?)`
          )
          .run(
            publicKey.fingerprint,
            challenge.endpoint_id,
            challengeId,
            publicKey.algorithm,
            publicKey.canonicalBase64,
            now.toISOString()
          );
      }
      this.audit.append(
        existing ? "endpoint.public-key.rebound" : "endpoint.public-key.registered",
        {
          algorithm: publicKey.algorithm,
          publicKeyFormat: "spki-der",
          keyProfile: ENDPOINT_KEY_PROFILES[publicKey.algorithm],
          certificateFingerprintSha256: publicKey.fingerprint,
          endpointId: challenge.endpoint_id,
          enrollmentChallengeId: challengeId,
          ...(existing
            ? {
                previousEndpointId: existing.endpoint_id,
                previousEnrollmentChallengeId: existing.enrollment_challenge_id
              }
            : {})
        },
        now
      );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
    return {
      algorithm: publicKey.algorithm,
      publicKeyFormat: "spki-der",
      certificateFingerprintSha256: publicKey.fingerprint,
      endpointId: challenge.endpoint_id,
      enrollmentChallengeId: challengeId,
      registeredAt: now.toISOString()
    };
  }

  readonly verifyEnrollmentProof: EnrollmentProofVerifier = (
    payload,
    signatureBase64,
    certificateFingerprintSha256
  ) => {
    try {
      const fingerprint = fingerprintSchema.parse(certificateFingerprintSha256);
      const parsed = enrollmentPayloadSchema.parse(JSON.parse(payload));
      if (
        parsed.certificateFingerprintSha256 !== fingerprint ||
        stableJson(parsed) !== payload
      ) {
        return false;
      }
      const row = this.database
        .prepare(
          `SELECT key.certificate_fingerprint_sha256, key.endpoint_id,
                  key.enrollment_challenge_id, key.algorithm,
                  key.public_key_spki_base64,
                  challenge.challenge_json,
                  challenge.status AS challenge_status
           FROM endpoint_public_keys key
           JOIN endpoint_enrollment_challenges challenge
             ON challenge.id = key.enrollment_challenge_id
           WHERE key.certificate_fingerprint_sha256 = ?`
        )
        .get(fingerprint) as unknown as EnrollmentKeyRow | undefined;
      if (
        !row ||
        row.challenge_status !== "pending" ||
        row.enrollment_challenge_id !== parsed.challengeId ||
        row.endpoint_id !== parsed.endpointId ||
        row.challenge_json !== payload
      ) {
        return false;
      }
      return verifyEndpointSignature(
        row.algorithm,
        payload,
        signatureBase64,
        row.public_key_spki_base64
      );
    } catch {
      return false;
    }
  };

  readonly verifyTelemetrySignature: TelemetrySignatureVerifier = (
    payload,
    signatureBase64,
    certificateFingerprintSha256
  ) => {
    try {
      const fingerprint = fingerprintSchema.parse(certificateFingerprintSha256);
      const parsed = endpointSignedPayloadBindingSchema.parse(JSON.parse(payload));
      if (
        parsed.certificateFingerprintSha256 !== fingerprint ||
        stableJson(parsed) !== payload
      ) {
        return false;
      }
      const row = this.database
        .prepare(
          `SELECT key.certificate_fingerprint_sha256, key.endpoint_id,
                  identity.connector_id, identity.mission_id,
                  identity.status AS identity_status,
                  key.algorithm, key.public_key_spki_base64
           FROM endpoint_public_keys key
           JOIN endpoint_identities identity
             ON identity.endpoint_id = key.endpoint_id
            AND identity.certificate_fingerprint_sha256 =
                key.certificate_fingerprint_sha256
           WHERE key.certificate_fingerprint_sha256 = ?`
        )
        .get(fingerprint) as unknown as TelemetryKeyRow | undefined;
      if (
        !row ||
        row.identity_status !== "active" ||
        row.endpoint_id !== parsed.endpointId ||
        row.connector_id !== parsed.connectorId ||
        row.mission_id !== parsed.missionId
      ) {
        return false;
      }
      return verifyEndpointSignature(
        row.algorithm,
        payload,
        signatureBase64,
        row.public_key_spki_base64
      );
    } catch {
      return false;
    }
  };
}
