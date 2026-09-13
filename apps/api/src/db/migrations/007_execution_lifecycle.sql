CREATE TABLE IF NOT EXISTS execution_lifecycles (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id),
  run_id TEXT REFERENCES runs(id),
  capability_id TEXT NOT NULL,
  operator TEXT NOT NULL,
  binary_sha256 TEXT CHECK (binary_sha256 IS NULL OR (length(binary_sha256) = 64 AND binary_sha256 NOT GLOB '*[^0-9a-f]*')),
  config_sha256 TEXT CHECK (config_sha256 IS NULL OR (length(config_sha256) = 64 AND config_sha256 NOT GLOB '*[^0-9a-f]*')),
  status TEXT NOT NULL CHECK (
    status IN (
      'queued',
      'starting',
      'running',
      'succeeded',
      'failed',
      'cancel_requested',
      'cancelled',
      'timed_out',
      'orphaned'
    )
  ),
  failure_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS execution_lifecycle_transitions (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  execution_id TEXT NOT NULL REFERENCES execution_lifecycles(id),
  from_status TEXT,
  to_status TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  reason_code TEXT
);

CREATE INDEX IF NOT EXISTS execution_lifecycles_status_idx
ON execution_lifecycles(status);

CREATE INDEX IF NOT EXISTS execution_lifecycle_transitions_execution_idx
ON execution_lifecycle_transitions(execution_id, sequence);

CREATE TRIGGER IF NOT EXISTS execution_lifecycle_binding_immutable
BEFORE UPDATE OF id, mission_id, run_id, capability_id, operator, binary_sha256, config_sha256, created_at
ON execution_lifecycles
BEGIN
  SELECT RAISE(ABORT, 'EXECUTION_BINDING_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS execution_lifecycle_status_transition_valid
BEFORE UPDATE OF status ON execution_lifecycles
WHEN NOT (
  (OLD.status = 'queued' AND NEW.status IN ('starting', 'cancel_requested', 'orphaned'))
  OR (OLD.status = 'starting' AND NEW.status IN ('running', 'failed', 'cancel_requested', 'timed_out', 'orphaned'))
  OR (OLD.status = 'running' AND NEW.status IN ('succeeded', 'failed', 'cancel_requested', 'timed_out', 'orphaned'))
  OR (OLD.status = 'cancel_requested' AND NEW.status IN ('cancelled', 'failed', 'timed_out', 'orphaned'))
)
BEGIN
  SELECT RAISE(ABORT, 'EXECUTION_STATUS_TRANSITION_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS execution_lifecycle_transitions_immutable_update
BEFORE UPDATE ON execution_lifecycle_transitions
BEGIN
  SELECT RAISE(ABORT, 'EXECUTION_TRANSITION_HISTORY_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS execution_lifecycle_transitions_immutable_delete
BEFORE DELETE ON execution_lifecycle_transitions
BEGIN
  SELECT RAISE(ABORT, 'EXECUTION_TRANSITION_HISTORY_IMMUTABLE');
END;
