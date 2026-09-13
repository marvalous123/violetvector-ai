PRAGMA foreign_keys = OFF;
PRAGMA legacy_alter_table = ON;
BEGIN IMMEDIATE;

DROP TRIGGER IF EXISTS endpoint_capability_binding_guard;
DROP TRIGGER IF EXISTS endpoint_capability_immutable_update;
DROP TRIGGER IF EXISTS endpoint_capability_immutable_delete;
DROP INDEX IF EXISTS idx_endpoint_capability_stream_observed;

ALTER TABLE endpoint_capability_snapshots
  RENAME TO endpoint_capability_snapshots_v2;

CREATE TABLE endpoint_capability_snapshots (
  id TEXT PRIMARY KEY,
  report_hash TEXT NOT NULL UNIQUE CHECK (length(report_hash) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  connector_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  certificate_fingerprint_sha256 TEXT NOT NULL
    CHECK (length(certificate_fingerprint_sha256) = 64),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  provider TEXT NOT NULL CHECK (
    provider IN (
      'windows-security',
      'windows-scm',
      'windows-sysmon',
      'windows-defender',
      'windows-eventlog',
      'windows-firewall'
    )
  ),
  channel TEXT NOT NULL CHECK (
    channel IN (
      'security',
      'system',
      'sysmon-operational',
      'defender-operational',
      'eventlog-admin',
      'firewall-operational'
    )
  ),
  event_family TEXT NOT NULL CHECK (
    event_family IN (
      'process-start',
      'process-access',
      'file-access',
      'authentication',
      'ticket-request',
      'authentication-component-change',
      'certificate-key-access',
      'image-load',
      'file-attribute-change',
      'security-control-change',
      'event-log-impairment',
      'event-log-clear',
      'firewall-policy-change',
      'scheduled-task-change',
      'service-change'
    )
  ),
  fields_json TEXT NOT NULL,
  fields_hash TEXT NOT NULL CHECK (length(fields_hash) = 64),
  filter_hash TEXT NOT NULL CHECK (length(filter_hash) = 64),
  collector_version TEXT NOT NULL,
  loss_state TEXT NOT NULL CHECK (loss_state IN ('none', 'reported', 'unknown')),
  lost_record_count INTEGER CHECK (
    lost_record_count IS NULL
    OR (lost_record_count >= 0 AND lost_record_count <= 1000000000)
  ),
  continuity_state TEXT NOT NULL CHECK (
    continuity_state IN ('continuous', 'gap', 'unknown')
  ),
  continuous_since TEXT NOT NULL,
  last_successful_read_at TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  fresh_until TEXT NOT NULL,
  evidence_artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id),
  recorded_at TEXT NOT NULL,
  CHECK (
    (loss_state = 'none' AND lost_record_count = 0)
    OR (loss_state = 'reported' AND lost_record_count > 0)
    OR (loss_state = 'unknown' AND lost_record_count IS NULL)
  ),
  UNIQUE (
    endpoint_id,
    provider,
    channel,
    event_family,
    observed_at,
    filter_hash
  )
);

INSERT INTO endpoint_capability_snapshots(
  id, report_hash, mission_id, connector_id, endpoint_id,
  certificate_fingerprint_sha256, schema_version, provider, channel,
  event_family, fields_json, fields_hash, filter_hash, collector_version,
  loss_state, lost_record_count, continuity_state, continuous_since,
  last_successful_read_at, observed_at, fresh_until, evidence_artifact_id,
  recorded_at
)
SELECT
  id, report_hash, mission_id, connector_id, endpoint_id,
  certificate_fingerprint_sha256, schema_version, provider, channel,
  event_family, fields_json, fields_hash, filter_hash, collector_version,
  loss_state, lost_record_count, continuity_state, continuous_since,
  last_successful_read_at, observed_at, fresh_until, evidence_artifact_id,
  recorded_at
FROM endpoint_capability_snapshots_v2;

DROP TABLE endpoint_capability_snapshots_v2;

CREATE INDEX idx_endpoint_capability_stream_observed
  ON endpoint_capability_snapshots(
    mission_id,
    endpoint_id,
    provider,
    channel,
    event_family,
    observed_at
  );

CREATE TRIGGER endpoint_capability_binding_guard
BEFORE INSERT ON endpoint_capability_snapshots
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_identities identity
  WHERE identity.endpoint_id = NEW.endpoint_id
    AND identity.connector_id = NEW.connector_id
    AND identity.mission_id = NEW.mission_id
    AND identity.certificate_fingerprint_sha256 = NEW.certificate_fingerprint_sha256
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_CAPABILITY_BINDING_INVALID');
END;

CREATE TRIGGER endpoint_capability_immutable_update
BEFORE UPDATE ON endpoint_capability_snapshots
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_CAPABILITY_IMMUTABLE');
END;

CREATE TRIGGER endpoint_capability_immutable_delete
BEFORE DELETE ON endpoint_capability_snapshots
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_CAPABILITY_IMMUTABLE');
END;

COMMIT;
PRAGMA legacy_alter_table = OFF;
PRAGMA foreign_keys = ON;
