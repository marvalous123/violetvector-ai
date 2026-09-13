CREATE TABLE IF NOT EXISTS report_export_bundles (
  id TEXT PRIMARY KEY,
  snapshot_id TEXT NOT NULL UNIQUE REFERENCES report_snapshots(id),
  mission_id TEXT NOT NULL REFERENCES missions(id),
  source_qa_review_id TEXT NOT NULL REFERENCES report_qa_reviews(id),
  source_snapshot_hash TEXT NOT NULL CHECK (length(source_snapshot_hash) = 64),
  json_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  json_sha256 TEXT NOT NULL CHECK (length(json_sha256) = 64),
  html_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  html_sha256 TEXT NOT NULL CHECK (length(html_sha256) = 64),
  pdf_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  pdf_sha256 TEXT NOT NULL CHECK (length(pdf_sha256) = 64),
  docx_artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  docx_sha256 TEXT NOT NULL CHECK (length(docx_sha256) = 64),
  generator_version TEXT NOT NULL CHECK (length(generator_version) BETWEEN 3 AND 80),
  generated_by TEXT NOT NULL CHECK (length(generated_by) BETWEEN 2 AND 120),
  generated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS report_export_qa_events (
  id TEXT PRIMARY KEY,
  bundle_id TEXT NOT NULL REFERENCES report_export_bundles(id),
  sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 10),
  event_type TEXT NOT NULL CHECK (event_type IN ('opened', 'approved', 'changes-requested')),
  payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 16384),
  payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
  actor TEXT NOT NULL CHECK (length(actor) BETWEEN 2 AND 120),
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT NOT NULL CHECK (length(previous_event_hash) = 64),
  event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
  UNIQUE (bundle_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_report_export_bundles_mission
  ON report_export_bundles(mission_id, generated_at);

CREATE INDEX IF NOT EXISTS idx_report_export_qa_events_bundle
  ON report_export_qa_events(bundle_id, sequence);

CREATE TRIGGER IF NOT EXISTS report_export_bundle_binding_guard
BEFORE INSERT ON report_export_bundles
WHEN NOT EXISTS (
  SELECT 1
  FROM report_snapshots snapshot
  JOIN report_qa_reviews review
    ON review.id = NEW.source_qa_review_id
   AND review.snapshot_id = snapshot.id
   AND review.mission_id = snapshot.mission_id
   AND review.snapshot_hash = snapshot.snapshot_hash
  WHERE snapshot.id = NEW.snapshot_id
    AND snapshot.mission_id = NEW.mission_id
    AND snapshot.snapshot_hash = NEW.source_snapshot_hash
    AND snapshot.status = 'generated'
)
BEGIN
  SELECT RAISE(ABORT, 'REPORT_EXPORT_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS report_export_qa_sequence_guard
BEFORE INSERT ON report_export_qa_events
WHEN NEW.sequence <> (
  SELECT COALESCE(MAX(sequence), 0) + 1
  FROM report_export_qa_events
  WHERE bundle_id = NEW.bundle_id
)
OR NEW.previous_event_hash <> COALESCE(
  (
    SELECT event_hash
    FROM report_export_qa_events
    WHERE bundle_id = NEW.bundle_id
    ORDER BY sequence DESC
    LIMIT 1
  ),
  '0000000000000000000000000000000000000000000000000000000000000000'
)
BEGIN
  SELECT RAISE(ABORT, 'REPORT_EXPORT_QA_CHAIN_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS report_export_bundles_immutable_update
BEFORE UPDATE ON report_export_bundles
BEGIN
  SELECT RAISE(ABORT, 'REPORT_EXPORT_BUNDLE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_export_bundles_immutable_delete
BEFORE DELETE ON report_export_bundles
BEGIN
  SELECT RAISE(ABORT, 'REPORT_EXPORT_BUNDLE_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_export_qa_events_immutable_update
BEFORE UPDATE ON report_export_qa_events
BEGIN
  SELECT RAISE(ABORT, 'REPORT_EXPORT_QA_EVENT_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS report_export_qa_events_immutable_delete
BEFORE DELETE ON report_export_qa_events
BEGIN
  SELECT RAISE(ABORT, 'REPORT_EXPORT_QA_EVENT_IMMUTABLE');
END;
