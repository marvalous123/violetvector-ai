DROP TRIGGER IF EXISTS endpoint_public_key_immutable_update;

CREATE TRIGGER endpoint_public_key_rebind_guard
BEFORE UPDATE OF endpoint_id, enrollment_challenge_id, registered_at
ON endpoint_public_keys
WHEN NOT (
  NEW.endpoint_id <> OLD.endpoint_id
  AND NEW.enrollment_challenge_id <> OLD.enrollment_challenge_id
  AND NEW.registered_at > OLD.registered_at
  AND EXISTS (
    SELECT 1
    FROM endpoint_enrollment_challenges previous
    WHERE previous.id = OLD.enrollment_challenge_id
      AND previous.endpoint_id = OLD.endpoint_id
      AND previous.certificate_fingerprint_sha256 =
          OLD.certificate_fingerprint_sha256
      AND previous.status = 'expired'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM endpoint_identities identity
    WHERE identity.certificate_fingerprint_sha256 =
        OLD.certificate_fingerprint_sha256
  )
  AND EXISTS (
    SELECT 1
    FROM endpoint_enrollment_challenges pending
    WHERE pending.id = NEW.enrollment_challenge_id
      AND pending.endpoint_id = NEW.endpoint_id
      AND pending.certificate_fingerprint_sha256 =
          NEW.certificate_fingerprint_sha256
      AND pending.status = 'pending'
      AND pending.requested_at <= NEW.registered_at
      AND pending.expires_at > NEW.registered_at
  )
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_PUBLIC_KEY_REBIND_INVALID');
END;

CREATE TRIGGER endpoint_public_key_immutable_update
BEFORE UPDATE OF certificate_fingerprint_sha256, algorithm,
  public_key_format, public_key_spki_base64
ON endpoint_public_keys
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_PUBLIC_KEY_IMMUTABLE');
END;
