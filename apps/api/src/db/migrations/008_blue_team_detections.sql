CREATE TABLE IF NOT EXISTS blue_detection_runs (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  scenario_id TEXT NOT NULL CHECK (
    scenario_id IN (
      'credential-access',
      'payload-execution',
      'defense-evasion',
      'combined-incident'
    )
  ),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  rule_set_version TEXT NOT NULL,
  event_count INTEGER NOT NULL CHECK (event_count >= 1 AND event_count <= 64),
  alert_count INTEGER NOT NULL CHECK (alert_count >= 0 AND alert_count <= 32),
  result_json TEXT NOT NULL,
  result_hash TEXT NOT NULL CHECK (length(result_hash) = 64),
  evidence_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  operator TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blue_detection_runs_mission_created
  ON blue_detection_runs(mission_id, created_at);

CREATE TRIGGER IF NOT EXISTS blue_detection_runs_immutable_update
BEFORE UPDATE ON blue_detection_runs
BEGIN
  SELECT RAISE(ABORT, 'BLUE_DETECTION_RUN_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS blue_detection_runs_immutable_delete
BEFORE DELETE ON blue_detection_runs
BEGIN
  SELECT RAISE(ABORT, 'BLUE_DETECTION_RUN_IMMUTABLE');
END;
