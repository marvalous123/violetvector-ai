CREATE TABLE IF NOT EXISTS remediation_records (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_events (
  id TEXT PRIMARY KEY,
  remediation_id TEXT NOT NULL REFERENCES remediation_records(id),
  sequence INTEGER NOT NULL CHECK (sequence >= 1 AND sequence <= 2000),
  event_type TEXT NOT NULL CHECK (
    event_type IN (
      'created',
      'owner-changed',
      'due-date-changed',
      'priority-changed',
      'status-changed',
      'reviewer-commented',
      'risk-acceptance-recorded',
      'risk-acceptance-revoked',
      'fix-evidence-added',
      'retest-requested',
      'retest-outcome-recorded'
    )
  ),
  payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 32768),
  payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 2 AND 120),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT NOT NULL CHECK (length(previous_event_hash) = 64),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
  UNIQUE (remediation_id, sequence)
);

CREATE TABLE IF NOT EXISTS remediation_evidence_links (
  remediation_event_id TEXT NOT NULL REFERENCES remediation_events(id),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  observation_id TEXT NOT NULL REFERENCES evidence_observations(id),
  purpose TEXT NOT NULL CHECK (purpose IN ('fix', 'retest')),
  PRIMARY KEY (remediation_event_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_records_mission
  ON remediation_records(mission_id, created_at);

CREATE INDEX IF NOT EXISTS idx_remediation_events_record
  ON remediation_events(remediation_id, sequence);

CREATE INDEX IF NOT EXISTS idx_remediation_evidence_artifact
  ON remediation_evidence_links(artifact_id, remediation_event_id);

CREATE TRIGGER IF NOT EXISTS remediation_record_requires_accepted_finding
BEFORE INSERT ON remediation_records
WHEN NOT EXISTS (
  SELECT 1
  FROM findings
  WHERE findings.id = NEW.finding_id
    AND findings.mission_id = NEW.mission_id
    AND findings.status = 'accepted'
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_ACCEPTED_FINDING_REQUIRED');
END;

CREATE TRIGGER IF NOT EXISTS remediation_event_sequence_guard
BEFORE INSERT ON remediation_events
WHEN NEW.sequence <> (
  SELECT COALESCE(MAX(sequence), 0) + 1
  FROM remediation_events
  WHERE remediation_id = NEW.remediation_id
)
OR NEW.previous_event_hash <> COALESCE(
  (
    SELECT event_hash
    FROM remediation_events
    WHERE remediation_id = NEW.remediation_id
    ORDER BY sequence DESC
    LIMIT 1
  ),
  '0000000000000000000000000000000000000000000000000000000000000000'
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVENT_CHAIN_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS remediation_evidence_mission_guard
BEFORE INSERT ON remediation_evidence_links
WHEN NOT EXISTS (
  SELECT 1
  FROM remediation_events event
  JOIN remediation_records record ON record.id = event.remediation_id
  JOIN evidence_observations observation
    ON observation.id = NEW.observation_id
   AND observation.artifact_id = NEW.artifact_id
   AND observation.mission_id = record.mission_id
  WHERE event.id = NEW.remediation_event_id
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVIDENCE_MISSION_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS remediation_evidence_purpose_guard
BEFORE INSERT ON remediation_evidence_links
WHEN NOT EXISTS (
  SELECT 1
  FROM remediation_events
  WHERE remediation_events.id = NEW.remediation_event_id
    AND (
      (NEW.purpose = 'fix' AND remediation_events.event_type = 'fix-evidence-added')
      OR
      (NEW.purpose = 'retest' AND remediation_events.event_type = 'retest-outcome-recorded')
    )
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVIDENCE_PURPOSE_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS remediation_records_immutable_update
BEFORE UPDATE ON remediation_records
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_RECORD_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS remediation_records_immutable_delete
BEFORE DELETE ON remediation_records
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_RECORD_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS remediation_events_immutable_update
BEFORE UPDATE ON remediation_events
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVENT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS remediation_events_immutable_delete
BEFORE DELETE ON remediation_events
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVENT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS remediation_evidence_links_immutable_update
BEFORE UPDATE ON remediation_evidence_links
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVIDENCE_LINK_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS remediation_evidence_links_immutable_delete
BEFORE DELETE ON remediation_evidence_links
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_EVIDENCE_LINK_IMMUTABLE');
END;
