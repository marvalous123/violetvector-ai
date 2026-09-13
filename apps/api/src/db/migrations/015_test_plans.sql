CREATE TABLE IF NOT EXISTS engagement_test_plans (
  id TEXT PRIMARY KEY,
  mission_id TEXT NOT NULL REFERENCES missions(id),
  version INTEGER NOT NULL CHECK (version BETWEEN 1 AND 1000),
  title TEXT NOT NULL CHECK (length(title) BETWEEN 5 AND 160),
  objective TEXT NOT NULL CHECK (length(objective) BETWEEN 10 AND 4000),
  supersedes_plan_id TEXT REFERENCES engagement_test_plans(id),
  procedure_count INTEGER NOT NULL CHECK (procedure_count BETWEEN 1 AND 200),
  content_hash TEXT NOT NULL CHECK (
    length(content_hash) = 64
    AND content_hash NOT GLOB '*[^0-9a-f]*'
  ),
  created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 2 AND 120),
  created_at TEXT NOT NULL,
  UNIQUE (mission_id, version),
  UNIQUE (mission_id, content_hash)
);

CREATE TABLE IF NOT EXISTS test_plan_procedures (
  id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES engagement_test_plans(id),
  procedure_key TEXT NOT NULL CHECK (
    length(procedure_key) BETWEEN 2 AND 80
    AND procedure_key NOT GLOB '*[^a-z0-9._-]*'
  ),
  ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 200),
  title TEXT NOT NULL CHECK (length(title) BETWEEN 5 AND 160),
  objective TEXT NOT NULL CHECK (length(objective) BETWEEN 10 AND 4000),
  procedure_json TEXT NOT NULL CHECK (length(procedure_json) BETWEEN 2 AND 16384),
  state TEXT NOT NULL CHECK (
    state IN ('completed', 'skipped', 'blocked', 'not-applicable')
  ),
  rationale TEXT NOT NULL CHECK (length(rationale) BETWEEN 10 AND 4000),
  capability_id TEXT,
  blue_rule_id TEXT,
  run_id TEXT REFERENCES runs(id),
  evidence_count INTEGER NOT NULL CHECK (evidence_count BETWEEN 0 AND 16),
  created_at TEXT NOT NULL,
  UNIQUE (plan_id, procedure_key),
  UNIQUE (plan_id, ordinal),
  CHECK (capability_id IS NOT NULL OR blue_rule_id IS NOT NULL),
  CHECK (state <> 'completed' OR evidence_count >= 1)
);

CREATE TABLE IF NOT EXISTS test_plan_procedure_evidence (
  procedure_id TEXT NOT NULL REFERENCES test_plan_procedures(id),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  observation_id TEXT NOT NULL REFERENCES evidence_observations(id),
  artifact_sha256 TEXT NOT NULL CHECK (
    length(artifact_sha256) = 64
    AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
  ),
  PRIMARY KEY (procedure_id, artifact_id)
);

CREATE INDEX IF NOT EXISTS idx_engagement_test_plans_mission
  ON engagement_test_plans(mission_id, version DESC);

CREATE INDEX IF NOT EXISTS idx_test_plan_procedures_plan
  ON test_plan_procedures(plan_id, ordinal);

CREATE INDEX IF NOT EXISTS idx_test_plan_procedure_evidence_artifact
  ON test_plan_procedure_evidence(artifact_id, procedure_id);

CREATE TRIGGER IF NOT EXISTS engagement_test_plan_supersedes_guard
BEFORE INSERT ON engagement_test_plans
WHEN
  (NEW.version = 1 AND NEW.supersedes_plan_id IS NOT NULL)
  OR
  (
    NEW.version > 1
    AND NOT EXISTS (
      SELECT 1
      FROM engagement_test_plans previous
      WHERE previous.id = NEW.supersedes_plan_id
        AND previous.mission_id = NEW.mission_id
        AND previous.version = NEW.version - 1
    )
  )
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_VERSION_LINEAGE_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS test_plan_procedure_run_mission_guard
BEFORE INSERT ON test_plan_procedures
WHEN NEW.run_id IS NOT NULL
AND NOT EXISTS (
  SELECT 1
  FROM engagement_test_plans plan
  JOIN runs run
    ON run.id = NEW.run_id
   AND run.mission_id = plan.mission_id
  WHERE plan.id = NEW.plan_id
)
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_RUN_MISSION_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS test_plan_procedure_evidence_guard
BEFORE INSERT ON test_plan_procedure_evidence
WHEN NOT EXISTS (
  SELECT 1
  FROM test_plan_procedures procedure
  JOIN engagement_test_plans plan ON plan.id = procedure.plan_id
  JOIN evidence_observations observation
    ON observation.id = NEW.observation_id
   AND observation.artifact_id = NEW.artifact_id
   AND observation.mission_id = plan.mission_id
  JOIN artifacts artifact
    ON artifact.id = NEW.artifact_id
   AND artifact.sha256 = NEW.artifact_sha256
  WHERE procedure.id = NEW.procedure_id
)
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_EVIDENCE_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS engagement_test_plans_immutable_update
BEFORE UPDATE ON engagement_test_plans
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS engagement_test_plans_immutable_delete
BEFORE DELETE ON engagement_test_plans
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS test_plan_procedures_immutable_update
BEFORE UPDATE ON test_plan_procedures
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_PROCEDURE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS test_plan_procedures_immutable_delete
BEFORE DELETE ON test_plan_procedures
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_PROCEDURE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS test_plan_procedure_evidence_immutable_update
BEFORE UPDATE ON test_plan_procedure_evidence
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_EVIDENCE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS test_plan_procedure_evidence_immutable_delete
BEFORE DELETE ON test_plan_procedure_evidence
BEGIN
  SELECT RAISE(ABORT, 'TEST_PLAN_EVIDENCE_IMMUTABLE');
END;
