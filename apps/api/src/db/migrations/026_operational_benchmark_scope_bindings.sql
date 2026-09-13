CREATE TABLE IF NOT EXISTS operational_benchmark_scope_bindings (
  benchmark_id TEXT PRIMARY KEY REFERENCES operational_benchmarks(id),
  scope_version_id TEXT NOT NULL REFERENCES scope_versions(id),
  authorization_record_id TEXT NOT NULL REFERENCES authorization_records(id),
  bound_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operational_benchmark_scope_bindings_scope
  ON operational_benchmark_scope_bindings(scope_version_id, authorization_record_id);

CREATE TRIGGER IF NOT EXISTS operational_benchmark_scope_binding_guard
BEFORE INSERT ON operational_benchmark_scope_bindings
WHEN NOT EXISTS (
  SELECT 1
  FROM operational_benchmarks benchmark
  JOIN scope_versions scope
    ON scope.id = NEW.scope_version_id
   AND scope.mission_id = benchmark.mission_id
  JOIN authorization_records authorization
    ON authorization.id = NEW.authorization_record_id
   AND authorization.scope_version_id = scope.id
  WHERE benchmark.id = NEW.benchmark_id
    AND scope.starts_at <= benchmark.started_at
    AND benchmark.started_at < scope.expires_at
    AND authorization.recorded_at <= benchmark.started_at
    AND NEW.bound_at = benchmark.started_at
)
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_SCOPE_BINDING_INVALID');
END;

WITH candidates AS (
  SELECT
    benchmark.id AS benchmark_id,
    scope.id AS scope_version_id,
    authorization.id AS authorization_record_id,
    benchmark.started_at AS bound_at,
    ROW_NUMBER() OVER (
      PARTITION BY benchmark.id
      ORDER BY scope.version DESC, authorization.recorded_at DESC, authorization.id DESC
    ) AS candidate_rank
  FROM operational_benchmarks benchmark
  JOIN scope_versions scope
    ON scope.mission_id = benchmark.mission_id
   AND scope.starts_at <= benchmark.started_at
   AND benchmark.started_at < scope.expires_at
  JOIN authorization_records authorization
    ON authorization.scope_version_id = scope.id
   AND authorization.recorded_at <= benchmark.started_at
)
INSERT INTO operational_benchmark_scope_bindings(
  benchmark_id, scope_version_id, authorization_record_id, bound_at
)
SELECT benchmark_id, scope_version_id, authorization_record_id, bound_at
FROM candidates
WHERE candidate_rank = 1;

CREATE TRIGGER IF NOT EXISTS operational_benchmark_scope_bindings_immutable_update
BEFORE UPDATE ON operational_benchmark_scope_bindings
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_SCOPE_BINDING_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS operational_benchmark_scope_bindings_immutable_delete
BEFORE DELETE ON operational_benchmark_scope_bindings
BEGIN
  SELECT RAISE(ABORT, 'OPERATIONAL_BENCHMARK_SCOPE_BINDING_IMMUTABLE');
END;
