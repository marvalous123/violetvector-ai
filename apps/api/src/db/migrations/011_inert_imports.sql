CREATE TABLE IF NOT EXISTS inert_imports (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  parent_import_id TEXT REFERENCES inert_imports(id),
  source_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  source_observation_id TEXT NOT NULL REFERENCES evidence_observations(id),
  source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64),
  source_size_bytes INTEGER NOT NULL CHECK (source_size_bytes > 0 AND source_size_bytes <= 2097152),
  source_media_type TEXT NOT NULL CHECK (source_media_type = 'application/sarif+json'),
  parser_id TEXT NOT NULL CHECK (parser_id = 'sarif-2.1.0-inert'),
  parser_version TEXT NOT NULL CHECK (parser_version = '1.0.0'),
  result_count INTEGER NOT NULL CHECK (result_count >= 0 AND result_count <= 500),
  candidate_count INTEGER NOT NULL CHECK (
    candidate_count >= 0
    AND candidate_count <= result_count
    AND candidate_count <= 500
  ),
  import_manifest_json TEXT NOT NULL,
  import_manifest_hash TEXT NOT NULL CHECK (length(import_manifest_hash) = 64),
  imported_by TEXT NOT NULL CHECK (length(imported_by) BETWEEN 2 AND 120),
  imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_inert_imports_mission_created
  ON inert_imports(mission_id, imported_at, id);

CREATE INDEX IF NOT EXISTS idx_inert_imports_parent
  ON inert_imports(parent_import_id);

CREATE TABLE IF NOT EXISTS inert_import_candidates (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
  normalized_key_json TEXT NOT NULL,
  normalized_key_hash TEXT NOT NULL CHECK (length(normalized_key_hash) = 64),
  status TEXT NOT NULL CHECK (status = 'unverified'),
  first_seen_import_id TEXT NOT NULL REFERENCES inert_imports(id),
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_inert_candidates_mission_created
  ON inert_import_candidates(mission_id, created_at, id);

CREATE TABLE IF NOT EXISTS inert_import_observations (
  id TEXT PRIMARY KEY,
  import_id TEXT NOT NULL REFERENCES inert_imports(id),
  candidate_id TEXT NOT NULL REFERENCES inert_import_candidates(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  source_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  source_observation_id TEXT NOT NULL REFERENCES evidence_observations(id),
  run_index INTEGER NOT NULL CHECK (run_index >= 0 AND run_index < 16),
  result_index INTEGER NOT NULL CHECK (result_index >= 0 AND result_index < 500),
  normalized_json TEXT NOT NULL,
  normalized_hash TEXT NOT NULL CHECK (length(normalized_hash) = 64),
  observed_at TEXT NOT NULL,
  UNIQUE (import_id, run_index, result_index)
);

CREATE INDEX IF NOT EXISTS idx_inert_observations_candidate
  ON inert_import_observations(candidate_id, observed_at, id);

CREATE INDEX IF NOT EXISTS idx_inert_observations_mission
  ON inert_import_observations(mission_id, observed_at, id);

CREATE TRIGGER IF NOT EXISTS inert_import_parent_same_mission
BEFORE INSERT ON inert_imports
WHEN NEW.parent_import_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM inert_imports parent
    WHERE parent.id = NEW.parent_import_id
      AND parent.mission_id = NEW.mission_id
      AND parent.parser_id = NEW.parser_id
      AND parent.parser_version = NEW.parser_version
  )
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_PARENT_MISSION_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS inert_import_source_same_mission
BEFORE INSERT ON inert_imports
WHEN NOT EXISTS (
  SELECT 1
  FROM evidence_observations observation
  WHERE observation.id = NEW.source_observation_id
    AND observation.artifact_id = NEW.source_artifact_id
    AND observation.mission_id = NEW.mission_id
)
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_SOURCE_MISSION_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS inert_candidate_first_seen_same_mission
BEFORE INSERT ON inert_import_candidates
WHEN NOT EXISTS (
  SELECT 1
  FROM inert_imports imported
  WHERE imported.id = NEW.first_seen_import_id
    AND imported.mission_id = NEW.mission_id
)
BEGIN
  SELECT RAISE(ABORT, 'INERT_CANDIDATE_MISSION_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS inert_observation_bindings_same_mission
BEFORE INSERT ON inert_import_observations
WHEN NOT EXISTS (
  SELECT 1
  FROM inert_imports imported
  JOIN inert_import_candidates candidate
    ON candidate.id = NEW.candidate_id
  JOIN evidence_observations evidence
    ON evidence.id = NEW.source_observation_id
  WHERE imported.id = NEW.import_id
    AND imported.mission_id = NEW.mission_id
    AND imported.source_artifact_id = NEW.source_artifact_id
    AND imported.source_observation_id = NEW.source_observation_id
    AND candidate.mission_id = NEW.mission_id
    AND evidence.mission_id = NEW.mission_id
    AND evidence.artifact_id = NEW.source_artifact_id
)
BEGIN
  SELECT RAISE(ABORT, 'INERT_OBSERVATION_BINDING_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS inert_imports_immutable_update
BEFORE UPDATE ON inert_imports
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS inert_imports_immutable_delete
BEFORE DELETE ON inert_imports
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS inert_import_candidates_immutable_update
BEFORE UPDATE ON inert_import_candidates
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_CANDIDATE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS inert_import_candidates_immutable_delete
BEFORE DELETE ON inert_import_candidates
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_CANDIDATE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS inert_import_observations_immutable_update
BEFORE UPDATE ON inert_import_observations
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_OBSERVATION_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS inert_import_observations_immutable_delete
BEFORE DELETE ON inert_import_observations
BEGIN
  SELECT RAISE(ABORT, 'INERT_IMPORT_OBSERVATION_IMMUTABLE');
END;
