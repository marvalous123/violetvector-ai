CREATE TABLE IF NOT EXISTS model_invocations (
  id TEXT PRIMARY KEY,
  mission_id TEXT REFERENCES missions(id),
  run_id TEXT REFERENCES runs(id),
  task_profile TEXT NOT NULL CHECK (
    task_profile IN ('structured-planning', 'evidence-summary', 'finding-draft')
  ),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started', 'succeeded', 'failed', 'rejected')),
  request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
  prompt_template_hash TEXT NOT NULL CHECK (length(prompt_template_hash) = 64),
  output_schema_hash TEXT NOT NULL CHECK (length(output_schema_hash) = 64),
  input_characters INTEGER NOT NULL CHECK (input_characters >= 0),
  output_characters INTEGER CHECK (output_characters >= 0),
  prompt_tokens INTEGER CHECK (prompt_tokens >= 0),
  completion_tokens INTEGER CHECK (completion_tokens >= 0),
  latency_ms INTEGER CHECK (latency_ms >= 0),
  result_json TEXT,
  error_code TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_model_invocations_mission_created
  ON model_invocations(mission_id, created_at);

CREATE INDEX IF NOT EXISTS idx_model_invocations_run_created
  ON model_invocations(run_id, created_at);

CREATE TABLE IF NOT EXISTS approval_scope_bindings (
  approval_id TEXT PRIMARY KEY REFERENCES approval_requests(id),
  scope_version_id TEXT NOT NULL REFERENCES scope_versions(id)
);
