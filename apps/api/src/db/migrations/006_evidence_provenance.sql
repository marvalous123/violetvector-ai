CREATE TABLE IF NOT EXISTS evidence_observations (
  id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  run_id TEXT REFERENCES runs(id),
  model_invocation_id TEXT REFERENCES model_invocations(id),
  source_event_id TEXT,
  provenance_json TEXT NOT NULL,
  provenance_hash TEXT NOT NULL CHECK (length(provenance_hash) = 64),
  captured_at TEXT NOT NULL,
  recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_observations_mission_artifact
  ON evidence_observations(mission_id, artifact_id, recorded_at);

CREATE INDEX IF NOT EXISTS idx_evidence_observations_run
  ON evidence_observations(run_id, recorded_at);

CREATE INDEX IF NOT EXISTS idx_evidence_observations_model
  ON evidence_observations(model_invocation_id, recorded_at);

CREATE TABLE IF NOT EXISTS finding_evidence_observations (
  finding_revision_id TEXT NOT NULL REFERENCES finding_revisions(id),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  observation_id TEXT NOT NULL REFERENCES evidence_observations(id),
  PRIMARY KEY (finding_revision_id, artifact_id)
);

CREATE TRIGGER IF NOT EXISTS evidence_observations_immutable_update
BEFORE UPDATE ON evidence_observations
BEGIN
  SELECT RAISE(ABORT, 'EVIDENCE_OBSERVATION_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS evidence_observations_immutable_delete
BEFORE DELETE ON evidence_observations
BEGIN
  SELECT RAISE(ABORT, 'EVIDENCE_OBSERVATION_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS finding_evidence_observations_immutable_update
BEFORE UPDATE ON finding_evidence_observations
BEGIN
  SELECT RAISE(ABORT, 'FINDING_EVIDENCE_CITATION_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS finding_evidence_observations_immutable_delete
BEFORE DELETE ON finding_evidence_observations
BEGIN
  SELECT RAISE(ABORT, 'FINDING_EVIDENCE_CITATION_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_snapshot_frozen_fields_immutable
BEFORE UPDATE ON report_snapshots
WHEN NEW.mission_id <> OLD.mission_id
  OR NEW.snapshot_json <> OLD.snapshot_json
  OR NEW.snapshot_hash <> OLD.snapshot_hash
  OR NEW.template_version <> OLD.template_version
  OR NEW.frozen_at <> OLD.frozen_at
BEGIN
  SELECT RAISE(ABORT, 'REPORT_SNAPSHOT_IMMUTABLE');
END;
