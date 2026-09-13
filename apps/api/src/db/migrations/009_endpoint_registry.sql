CREATE TABLE IF NOT EXISTS endpoint_enrollment_challenges (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  connector_id TEXT NOT NULL UNIQUE,
  endpoint_id TEXT NOT NULL UNIQUE,
  certificate_fingerprint_sha256 TEXT NOT NULL
    CHECK (length(certificate_fingerprint_sha256) = 64),
  challenge_json TEXT NOT NULL,
  challenge_hash TEXT NOT NULL UNIQUE CHECK (length(challenge_hash) = 64),
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'expired')),
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  identity_expires_at TEXT NOT NULL,
  approved_by TEXT,
  approved_at TEXT,
  CHECK (
    (status = 'approved' AND approved_by IS NOT NULL AND approved_at IS NOT NULL)
    OR
    (status IN ('pending', 'expired') AND approved_by IS NULL AND approved_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS idx_endpoint_enrollment_mission_status
  ON endpoint_enrollment_challenges(mission_id, status, expires_at);

CREATE INDEX IF NOT EXISTS idx_endpoint_enrollment_fingerprint_status
  ON endpoint_enrollment_challenges(certificate_fingerprint_sha256, status, expires_at);

CREATE TABLE IF NOT EXISTS endpoint_identities (
  endpoint_id TEXT PRIMARY KEY,
  connector_id TEXT NOT NULL UNIQUE,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  certificate_fingerprint_sha256 TEXT NOT NULL UNIQUE
    CHECK (length(certificate_fingerprint_sha256) = 64),
  enrollment_challenge_id TEXT NOT NULL UNIQUE
    REFERENCES endpoint_enrollment_challenges(id),
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked', 'expired')),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  approved_by TEXT NOT NULL,
  revoked_at TEXT,
  revoked_by TEXT,
  revocation_reason TEXT,
  current_boot_id TEXT,
  last_sequence INTEGER CHECK (last_sequence IS NULL OR last_sequence >= 0),
  last_batch_hash TEXT CHECK (last_batch_hash IS NULL OR length(last_batch_hash) = 64),
  last_receipt_hash TEXT CHECK (last_receipt_hash IS NULL OR length(last_receipt_hash) = 64),
  last_seen_at TEXT,
  CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL AND revoked_by IS NOT NULL AND revocation_reason IS NOT NULL)
    OR
    (status IN ('active', 'expired') AND revoked_at IS NULL AND revoked_by IS NULL AND revocation_reason IS NULL)
  ),
  CHECK (
    (
      current_boot_id IS NULL
      AND last_sequence IS NULL
      AND last_batch_hash IS NULL
      AND last_receipt_hash IS NULL
      AND last_seen_at IS NULL
    )
    OR
    (
      current_boot_id IS NOT NULL
      AND last_sequence IS NOT NULL
      AND last_batch_hash IS NOT NULL
      AND last_receipt_hash IS NOT NULL
      AND last_seen_at IS NOT NULL
    )
  )
);

CREATE INDEX IF NOT EXISTS idx_endpoint_identities_mission_status
  ON endpoint_identities(mission_id, status, expires_at);

CREATE TABLE IF NOT EXISTS endpoint_telemetry_batches (
  batch_id TEXT PRIMARY KEY,
  batch_hash TEXT NOT NULL UNIQUE CHECK (length(batch_hash) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  connector_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  certificate_fingerprint_sha256 TEXT NOT NULL
    CHECK (length(certificate_fingerprint_sha256) = 64),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  boot_id TEXT NOT NULL,
  sequence_start INTEGER NOT NULL CHECK (sequence_start >= 0),
  sequence_end INTEGER NOT NULL CHECK (sequence_end >= sequence_start),
  previous_batch_hash TEXT CHECK (
    previous_batch_hash IS NULL OR length(previous_batch_hash) = 64
  ),
  event_count INTEGER NOT NULL CHECK (event_count >= 1 AND event_count <= 256),
  evidence_artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id),
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL UNIQUE CHECK (length(receipt_hash) = 64),
  accepted_at TEXT NOT NULL,
  UNIQUE (connector_id, boot_id, sequence_start),
  UNIQUE (connector_id, boot_id, sequence_end)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_batches_connector_accepted
  ON endpoint_telemetry_batches(connector_id, accepted_at);

CREATE TRIGGER IF NOT EXISTS endpoint_batch_continuity_guard
BEFORE INSERT ON endpoint_telemetry_batches
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_identities identity
  WHERE identity.endpoint_id = NEW.endpoint_id
    AND identity.connector_id = NEW.connector_id
    AND identity.mission_id = NEW.mission_id
    AND identity.certificate_fingerprint_sha256 = NEW.certificate_fingerprint_sha256
    AND identity.status = 'active'
    AND identity.issued_at <= NEW.accepted_at
    AND identity.expires_at > NEW.accepted_at
    AND (
      (
        identity.current_boot_id IS NULL
        AND identity.last_sequence IS NULL
        AND identity.last_batch_hash IS NULL
        AND NEW.sequence_start = 0
        AND NEW.previous_batch_hash IS NULL
      )
      OR
      (
        identity.current_boot_id = NEW.boot_id
        AND identity.last_sequence IS NOT NULL
        AND NEW.sequence_start = identity.last_sequence + 1
        AND NEW.previous_batch_hash = identity.last_batch_hash
      )
      OR
      (
        identity.current_boot_id IS NOT NULL
        AND identity.current_boot_id <> NEW.boot_id
        AND identity.last_sequence IS NOT NULL
        AND NEW.sequence_start = 0
        AND NEW.previous_batch_hash = identity.last_batch_hash
      )
    )
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_BATCH_CONTINUITY_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_enrollment_core_immutable
BEFORE UPDATE ON endpoint_enrollment_challenges
WHEN NEW.mission_id <> OLD.mission_id
  OR NEW.connector_id <> OLD.connector_id
  OR NEW.endpoint_id <> OLD.endpoint_id
  OR NEW.certificate_fingerprint_sha256 <> OLD.certificate_fingerprint_sha256
  OR NEW.challenge_json <> OLD.challenge_json
  OR NEW.challenge_hash <> OLD.challenge_hash
  OR NEW.requested_by <> OLD.requested_by
  OR NEW.requested_at <> OLD.requested_at
  OR NEW.expires_at <> OLD.expires_at
  OR NEW.identity_expires_at <> OLD.identity_expires_at
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_ENROLLMENT_CORE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_enrollment_status_transition
BEFORE UPDATE OF status ON endpoint_enrollment_challenges
WHEN OLD.status <> NEW.status
  AND NOT (OLD.status = 'pending' AND NEW.status IN ('approved', 'expired'))
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_ENROLLMENT_STATUS_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_enrollment_immutable_delete
BEFORE DELETE ON endpoint_enrollment_challenges
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_ENROLLMENT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_binding_immutable
BEFORE UPDATE ON endpoint_identities
WHEN NEW.endpoint_id <> OLD.endpoint_id
  OR NEW.connector_id <> OLD.connector_id
  OR NEW.mission_id <> OLD.mission_id
  OR NEW.certificate_fingerprint_sha256 <> OLD.certificate_fingerprint_sha256
  OR NEW.enrollment_challenge_id <> OLD.enrollment_challenge_id
  OR NEW.issued_at <> OLD.issued_at
  OR NEW.expires_at <> OLD.expires_at
  OR NEW.approved_by <> OLD.approved_by
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_IDENTITY_BINDING_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_status_transition
BEFORE UPDATE OF status ON endpoint_identities
WHEN OLD.status <> NEW.status
  AND NOT (OLD.status = 'active' AND NEW.status IN ('revoked', 'expired'))
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_IDENTITY_STATUS_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_immutable_delete
BEFORE DELETE ON endpoint_identities
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_IDENTITY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_batch_immutable_update
BEFORE UPDATE ON endpoint_telemetry_batches
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_BATCH_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_batch_immutable_delete
BEFORE DELETE ON endpoint_telemetry_batches
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_BATCH_IMMUTABLE');
END;
