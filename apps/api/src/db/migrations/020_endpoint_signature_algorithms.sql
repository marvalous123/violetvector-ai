DROP TRIGGER IF EXISTS endpoint_public_key_binding_guard;
DROP TRIGGER IF EXISTS endpoint_public_key_immutable_update;
DROP TRIGGER IF EXISTS endpoint_public_key_immutable_delete;
DROP INDEX IF EXISTS idx_endpoint_public_keys_endpoint;

ALTER TABLE endpoint_public_keys RENAME TO endpoint_public_keys_ed25519_only;

CREATE TABLE endpoint_public_keys (
  certificate_fingerprint_sha256 TEXT PRIMARY KEY
    CHECK (length(certificate_fingerprint_sha256) = 64),
  endpoint_id TEXT NOT NULL UNIQUE,
  enrollment_challenge_id TEXT NOT NULL UNIQUE
    REFERENCES endpoint_enrollment_challenges(id),
  algorithm TEXT NOT NULL
    CHECK (algorithm IN ('ed25519', 'ecdsa-p256-sha256')),
  public_key_format TEXT NOT NULL CHECK (public_key_format = 'spki-der'),
  public_key_spki_base64 TEXT NOT NULL UNIQUE,
  registered_at TEXT NOT NULL,
  FOREIGN KEY (endpoint_id)
    REFERENCES endpoint_enrollment_challenges(endpoint_id)
);

INSERT INTO endpoint_public_keys(
  certificate_fingerprint_sha256,
  endpoint_id,
  enrollment_challenge_id,
  algorithm,
  public_key_format,
  public_key_spki_base64,
  registered_at
)
SELECT
  certificate_fingerprint_sha256,
  endpoint_id,
  enrollment_challenge_id,
  algorithm,
  public_key_format,
  public_key_spki_base64,
  registered_at
FROM endpoint_public_keys_ed25519_only;

DROP TABLE endpoint_public_keys_ed25519_only;

CREATE INDEX idx_endpoint_public_keys_endpoint
  ON endpoint_public_keys(endpoint_id, certificate_fingerprint_sha256);

CREATE TRIGGER endpoint_public_key_binding_guard
BEFORE INSERT ON endpoint_public_keys
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_enrollment_challenges challenge
  WHERE challenge.id = NEW.enrollment_challenge_id
    AND challenge.endpoint_id = NEW.endpoint_id
    AND challenge.certificate_fingerprint_sha256 = NEW.certificate_fingerprint_sha256
    AND challenge.status = 'pending'
    AND challenge.requested_at <= NEW.registered_at
    AND challenge.expires_at > NEW.registered_at
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_PUBLIC_KEY_BINDING_INVALID');
END;

CREATE TRIGGER endpoint_public_key_immutable_update
BEFORE UPDATE ON endpoint_public_keys
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_PUBLIC_KEY_IMMUTABLE');
END;

CREATE TRIGGER endpoint_public_key_immutable_delete
BEFORE DELETE ON endpoint_public_keys
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_PUBLIC_KEY_IMMUTABLE');
END;
