CREATE TABLE IF NOT EXISTS endpoint_identity_renewals (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  previous_endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  replacement_enrollment_challenge_id TEXT NOT NULL UNIQUE
    REFERENCES endpoint_enrollment_challenges(id),
  replacement_endpoint_id TEXT NOT NULL UNIQUE,
  previous_certificate_fingerprint_sha256 TEXT NOT NULL
    CHECK (length(previous_certificate_fingerprint_sha256) = 64),
  replacement_certificate_fingerprint_sha256 TEXT NOT NULL
    CHECK (length(replacement_certificate_fingerprint_sha256) = 64),
  status TEXT NOT NULL CHECK (status IN ('pending', 'activated', 'expired')),
  reason TEXT NOT NULL,
  requested_by TEXT NOT NULL,
  requested_at TEXT NOT NULL,
  challenge_expires_at TEXT NOT NULL,
  activated_by TEXT,
  activated_at TEXT,
  CHECK (
    previous_endpoint_id <> replacement_endpoint_id
    AND previous_certificate_fingerprint_sha256 <>
        replacement_certificate_fingerprint_sha256
  ),
  CHECK (
    (status = 'activated' AND activated_by IS NOT NULL AND activated_at IS NOT NULL)
    OR
    (status IN ('pending', 'expired') AND activated_by IS NULL AND activated_at IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS one_pending_renewal_per_endpoint
  ON endpoint_identity_renewals(previous_endpoint_id)
  WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_endpoint_renewals_mission_status
  ON endpoint_identity_renewals(mission_id, status, requested_at);

CREATE TRIGGER IF NOT EXISTS endpoint_identity_renewal_binding_guard
BEFORE INSERT ON endpoint_identity_renewals
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_identities previous
  JOIN endpoint_enrollment_challenges replacement
    ON replacement.id = NEW.replacement_enrollment_challenge_id
  WHERE previous.endpoint_id = NEW.previous_endpoint_id
    AND previous.mission_id = NEW.mission_id
    AND previous.status = 'active'
    AND previous.certificate_fingerprint_sha256 =
        NEW.previous_certificate_fingerprint_sha256
    AND replacement.mission_id = NEW.mission_id
    AND replacement.endpoint_id = NEW.replacement_endpoint_id
    AND replacement.certificate_fingerprint_sha256 =
        NEW.replacement_certificate_fingerprint_sha256
    AND replacement.status = 'pending'
    AND replacement.expires_at = NEW.challenge_expires_at
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_RENEWAL_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_renewal_activation_guard
BEFORE UPDATE OF status ON endpoint_identity_renewals
WHEN NEW.status = 'activated'
  AND NOT EXISTS (
    SELECT 1
    FROM endpoint_identities previous
    JOIN endpoint_identities replacement
      ON replacement.endpoint_id = NEW.replacement_endpoint_id
    WHERE previous.endpoint_id = NEW.previous_endpoint_id
      AND previous.status = 'revoked'
      AND replacement.mission_id = NEW.mission_id
      AND replacement.status = 'active'
      AND replacement.enrollment_challenge_id =
          NEW.replacement_enrollment_challenge_id
      AND replacement.certificate_fingerprint_sha256 =
          NEW.replacement_certificate_fingerprint_sha256
  )
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_RENEWAL_ACTIVATION_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_renewal_core_immutable
BEFORE UPDATE ON endpoint_identity_renewals
WHEN NEW.id <> OLD.id
  OR NEW.mission_id <> OLD.mission_id
  OR NEW.previous_endpoint_id <> OLD.previous_endpoint_id
  OR NEW.replacement_enrollment_challenge_id <>
      OLD.replacement_enrollment_challenge_id
  OR NEW.replacement_endpoint_id <> OLD.replacement_endpoint_id
  OR NEW.previous_certificate_fingerprint_sha256 <>
      OLD.previous_certificate_fingerprint_sha256
  OR NEW.replacement_certificate_fingerprint_sha256 <>
      OLD.replacement_certificate_fingerprint_sha256
  OR NEW.reason <> OLD.reason
  OR NEW.requested_by <> OLD.requested_by
  OR NEW.requested_at <> OLD.requested_at
  OR NEW.challenge_expires_at <> OLD.challenge_expires_at
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_RENEWAL_CORE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_renewal_status_transition
BEFORE UPDATE OF status ON endpoint_identity_renewals
WHEN OLD.status <> NEW.status
  AND NOT (OLD.status = 'pending' AND NEW.status IN ('activated', 'expired'))
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_RENEWAL_STATUS_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_renewal_activation_immutable
BEFORE UPDATE ON endpoint_identity_renewals
WHEN
  (
    OLD.status = 'pending'
    AND NEW.status = 'pending'
    AND (
      NEW.activated_by IS NOT OLD.activated_by
      OR NEW.activated_at IS NOT OLD.activated_at
    )
  )
  OR
  (
    OLD.status IN ('activated', 'expired')
    AND (
      NEW.activated_by IS NOT OLD.activated_by
      OR NEW.activated_at IS NOT OLD.activated_at
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_RENEWAL_ACTIVATION_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_identity_renewal_immutable_delete
BEFORE DELETE ON endpoint_identity_renewals
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_RENEWAL_IMMUTABLE');
END;
