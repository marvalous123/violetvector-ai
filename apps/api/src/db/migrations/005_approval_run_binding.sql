CREATE TABLE IF NOT EXISTS run_scope_bindings (
  run_id TEXT PRIMARY KEY REFERENCES runs(id),
  scope_version_id TEXT NOT NULL REFERENCES scope_versions(id),
  bound_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS safety_epochs (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  epoch INTEGER NOT NULL CHECK (epoch >= 0)
);

INSERT OR IGNORE INTO safety_epochs(id, epoch) VALUES (1, 0);

CREATE TABLE IF NOT EXISTS approval_execution_bindings (
  approval_id TEXT PRIMARY KEY REFERENCES approval_requests(id),
  run_id TEXT NOT NULL REFERENCES runs(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  scope_version_id TEXT NOT NULL REFERENCES scope_versions(id),
  target_id TEXT NOT NULL REFERENCES targets(id),
  canonical_target TEXT NOT NULL,
  authorization_starts_at TEXT NOT NULL,
  authorization_expires_at TEXT NOT NULL,
  capability_schema_hash TEXT NOT NULL CHECK (length(capability_schema_hash) = 64),
  safety_epoch INTEGER NOT NULL CHECK (safety_epoch >= 0),
  wall_time_ms_limit INTEGER NOT NULL,
  tool_time_ms_limit INTEGER NOT NULL,
  model_tokens_limit INTEGER NOT NULL,
  output_bytes_limit INTEGER NOT NULL,
  request_count_limit INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_execution_run
  ON approval_execution_bindings(run_id);
