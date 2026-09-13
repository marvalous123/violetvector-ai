CREATE TABLE IF NOT EXISTS mission_profiles (
  mission_id TEXT PRIMARY KEY REFERENCES missions(id),
  mode TEXT NOT NULL CHECK (mode = 'synthetic_demo'),
  template_version TEXT NOT NULL CHECK (template_version = 'guided-demo-v1'),
  execution_permitted INTEGER NOT NULL CHECK (execution_permitted = 0),
  boundary_text TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS guided_demo_instances (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL UNIQUE REFERENCES missions(id),
  blue_detection_run_id TEXT NOT NULL REFERENCES blue_detection_runs(id),
  finding_id TEXT NOT NULL REFERENCES findings(id),
  report_snapshot_id TEXT NOT NULL REFERENCES report_snapshots(id),
  json_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  html_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS mission_profiles_immutable_update
BEFORE UPDATE ON mission_profiles
BEGIN
  SELECT RAISE(ABORT, 'MISSION_PROFILE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS mission_profiles_immutable_delete
BEFORE DELETE ON mission_profiles
BEGIN
  SELECT RAISE(ABORT, 'MISSION_PROFILE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS guided_demo_instances_immutable_update
BEFORE UPDATE ON guided_demo_instances
BEGIN
  SELECT RAISE(ABORT, 'GUIDED_DEMO_INSTANCE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS guided_demo_instances_immutable_delete
BEFORE DELETE ON guided_demo_instances
BEGIN
  SELECT RAISE(ABORT, 'GUIDED_DEMO_INSTANCE_IMMUTABLE');
END;
