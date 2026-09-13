CREATE TABLE IF NOT EXISTS endpoint_capability_snapshots (
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
      'windows-sysmon',
      'windows-defender',
      'windows-eventlog',
      'windows-firewall'
    )
  ),
  channel TEXT NOT NULL CHECK (
    channel IN (
      'security',
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

CREATE INDEX IF NOT EXISTS idx_endpoint_capability_stream_observed
  ON endpoint_capability_snapshots(
    mission_id,
    endpoint_id,
    provider,
    channel,
    event_family,
    observed_at
  );

CREATE TABLE IF NOT EXISTS endpoint_fact_stream_heads (
  endpoint_id TEXT PRIMARY KEY REFERENCES endpoint_identities(endpoint_id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  connector_id TEXT NOT NULL,
  boot_id TEXT NOT NULL,
  last_batch_sequence INTEGER NOT NULL CHECK (last_batch_sequence >= 0),
  last_batch_hash TEXT NOT NULL CHECK (length(last_batch_hash) = 64),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoint_fact_batches (
  id TEXT PRIMARY KEY,
  batch_hash TEXT NOT NULL UNIQUE CHECK (length(batch_hash) = 64),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  connector_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  certificate_fingerprint_sha256 TEXT NOT NULL
    CHECK (length(certificate_fingerprint_sha256) = 64),
  capability_snapshot_id TEXT NOT NULL REFERENCES endpoint_capability_snapshots(id),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  boot_id TEXT NOT NULL,
  batch_sequence INTEGER NOT NULL CHECK (batch_sequence >= 0),
  previous_batch_hash TEXT CHECK (
    previous_batch_hash IS NULL OR length(previous_batch_hash) = 64
  ),
  provider TEXT NOT NULL,
  channel TEXT NOT NULL,
  event_family TEXT NOT NULL,
  filter_hash TEXT NOT NULL CHECK (length(filter_hash) = 64),
  fact_count INTEGER NOT NULL CHECK (fact_count >= 1 AND fact_count <= 128),
  first_occurred_at TEXT NOT NULL,
  last_occurred_at TEXT NOT NULL,
  evidence_artifact_id TEXT NOT NULL UNIQUE REFERENCES artifacts(id),
  accepted_at TEXT NOT NULL,
  UNIQUE(endpoint_id, boot_id, batch_sequence)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_fact_batches_stream_accepted
  ON endpoint_fact_batches(
    mission_id,
    endpoint_id,
    provider,
    channel,
    event_family,
    accepted_at
  );

CREATE TABLE IF NOT EXISTS endpoint_minimized_facts (
  fact_id TEXT PRIMARY KEY,
  fact_hash TEXT NOT NULL UNIQUE CHECK (length(fact_hash) = 64),
  batch_id TEXT NOT NULL REFERENCES endpoint_fact_batches(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  connector_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  capability_snapshot_id TEXT NOT NULL REFERENCES endpoint_capability_snapshots(id),
  provider TEXT NOT NULL,
  channel TEXT NOT NULL,
  event_family TEXT NOT NULL,
  filter_hash TEXT NOT NULL CHECK (length(filter_hash) = 64),
  occurred_at TEXT NOT NULL,
  source_record_id_hash TEXT NOT NULL CHECK (length(source_record_id_hash) = 64),
  fields_json TEXT NOT NULL,
  fields_hash TEXT NOT NULL CHECK (length(fields_hash) = 64),
  accepted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_endpoint_facts_mission_window
  ON endpoint_minimized_facts(
    mission_id,
    endpoint_id,
    occurred_at,
    event_family
  );

CREATE TABLE IF NOT EXISTS endpoint_live_correlation_runs (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  rule_set_version TEXT NOT NULL,
  selected_rule_ids_json TEXT NOT NULL,
  selected_rule_ids_hash TEXT NOT NULL CHECK (length(selected_rule_ids_hash) = 64),
  window_start TEXT NOT NULL,
  window_end TEXT NOT NULL,
  coverage_json TEXT NOT NULL,
  coverage_hash TEXT NOT NULL CHECK (length(coverage_hash) = 64),
  matched_fact_ids_json TEXT NOT NULL,
  matched_fact_ids_hash TEXT NOT NULL CHECK (length(matched_fact_ids_hash) = 64),
  status TEXT NOT NULL CHECK (status IN ('completed', 'blocked-coverage')),
  verdict TEXT NOT NULL CHECK (
    verdict IN (
      'reviewable-alerts-produced',
      'no-rule-match-observed',
      'coverage-blocked'
    )
  ),
  alert_count INTEGER NOT NULL CHECK (alert_count >= 0 AND alert_count <= 32),
  result_json TEXT NOT NULL,
  result_hash TEXT NOT NULL CHECK (length(result_hash) = 64),
  evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  operator TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_endpoint_live_runs_mission_created
  ON endpoint_live_correlation_runs(mission_id, endpoint_id, created_at);

CREATE TABLE IF NOT EXISTS endpoint_live_blue_alerts (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES endpoint_live_correlation_runs(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  endpoint_id TEXT NOT NULL REFERENCES endpoint_identities(endpoint_id),
  rule_id TEXT NOT NULL,
  signal TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('medium', 'high')),
  matched_fact_ids_json TEXT NOT NULL,
  matched_fact_ids_hash TEXT NOT NULL CHECK (length(matched_fact_ids_hash) = 64),
  reason TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK (disposition = 'needs-review'),
  created_at TEXT NOT NULL,
  UNIQUE(run_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_live_alerts_mission_created
  ON endpoint_live_blue_alerts(mission_id, endpoint_id, created_at);

CREATE TRIGGER IF NOT EXISTS endpoint_capability_binding_guard
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

CREATE TRIGGER IF NOT EXISTS endpoint_fact_batch_binding_guard
BEFORE INSERT ON endpoint_fact_batches
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_capability_snapshots capability
  JOIN endpoint_identities identity
    ON identity.endpoint_id = capability.endpoint_id
  WHERE capability.id = NEW.capability_snapshot_id
    AND capability.mission_id = NEW.mission_id
    AND capability.connector_id = NEW.connector_id
    AND capability.endpoint_id = NEW.endpoint_id
    AND capability.certificate_fingerprint_sha256 = NEW.certificate_fingerprint_sha256
    AND capability.provider = NEW.provider
    AND capability.channel = NEW.channel
    AND capability.event_family = NEW.event_family
    AND capability.filter_hash = NEW.filter_hash
    AND identity.mission_id = NEW.mission_id
    AND identity.connector_id = NEW.connector_id
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_BATCH_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_fact_batch_continuity_guard
BEFORE INSERT ON endpoint_fact_batches
WHEN NOT (
  (
    NOT EXISTS (
      SELECT 1 FROM endpoint_fact_stream_heads
      WHERE endpoint_id = NEW.endpoint_id
    )
    AND NEW.batch_sequence = 0
    AND NEW.previous_batch_hash IS NULL
  )
  OR EXISTS (
    SELECT 1
    FROM endpoint_fact_stream_heads head
    WHERE head.endpoint_id = NEW.endpoint_id
      AND head.mission_id = NEW.mission_id
      AND head.connector_id = NEW.connector_id
      AND NEW.previous_batch_hash = head.last_batch_hash
      AND (
        (
          NEW.boot_id = head.boot_id
          AND NEW.batch_sequence = head.last_batch_sequence + 1
        )
        OR
        (
          NEW.boot_id <> head.boot_id
          AND NEW.batch_sequence = 0
        )
      )
  )
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_CONTINUITY_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_minimized_fact_binding_guard
BEFORE INSERT ON endpoint_minimized_facts
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_fact_batches batch
  WHERE batch.id = NEW.batch_id
    AND batch.mission_id = NEW.mission_id
    AND batch.connector_id = NEW.connector_id
    AND batch.endpoint_id = NEW.endpoint_id
    AND batch.capability_snapshot_id = NEW.capability_snapshot_id
    AND batch.provider = NEW.provider
    AND batch.channel = NEW.channel
    AND batch.event_family = NEW.event_family
    AND batch.filter_hash = NEW.filter_hash
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_live_alert_binding_guard
BEFORE INSERT ON endpoint_live_blue_alerts
WHEN NOT EXISTS (
  SELECT 1
  FROM endpoint_live_correlation_runs run
  WHERE run.id = NEW.run_id
    AND run.mission_id = NEW.mission_id
    AND run.endpoint_id = NEW.endpoint_id
    AND run.status = 'completed'
    AND run.verdict = 'reviewable-alerts-produced'
)
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_LIVE_ALERT_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_capability_immutable_update
BEFORE UPDATE ON endpoint_capability_snapshots
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_CAPABILITY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_capability_immutable_delete
BEFORE DELETE ON endpoint_capability_snapshots
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_CAPABILITY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_fact_head_binding_immutable
BEFORE UPDATE ON endpoint_fact_stream_heads
WHEN NEW.endpoint_id <> OLD.endpoint_id
  OR NEW.mission_id <> OLD.mission_id
  OR NEW.connector_id <> OLD.connector_id
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_HEAD_BINDING_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_fact_head_immutable_delete
BEFORE DELETE ON endpoint_fact_stream_heads
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_HEAD_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_fact_batch_immutable_update
BEFORE UPDATE ON endpoint_fact_batches
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_BATCH_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_fact_batch_immutable_delete
BEFORE DELETE ON endpoint_fact_batches
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_FACT_BATCH_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_minimized_fact_immutable_update
BEFORE UPDATE ON endpoint_minimized_facts
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_MINIMIZED_FACT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_minimized_fact_immutable_delete
BEFORE DELETE ON endpoint_minimized_facts
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_MINIMIZED_FACT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_live_run_immutable_update
BEFORE UPDATE ON endpoint_live_correlation_runs
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_LIVE_RUN_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_live_run_immutable_delete
BEFORE DELETE ON endpoint_live_correlation_runs
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_LIVE_RUN_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_live_alert_immutable_update
BEFORE UPDATE ON endpoint_live_blue_alerts
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_LIVE_ALERT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS endpoint_live_alert_immutable_delete
BEFORE DELETE ON endpoint_live_blue_alerts
BEGIN
  SELECT RAISE(ABORT, 'ENDPOINT_LIVE_ALERT_IMMUTABLE');
END;
