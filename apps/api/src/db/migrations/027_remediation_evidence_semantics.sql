CREATE TABLE IF NOT EXISTS remediation_direct_retest_bindings (
  request_id TEXT PRIMARY KEY,
  remediation_id TEXT NOT NULL REFERENCES remediation_records(id),
  parent_run_id TEXT NOT NULL REFERENCES runs(id),
  retest_run_id TEXT NOT NULL UNIQUE REFERENCES runs(id),
  approval_id TEXT NOT NULL UNIQUE REFERENCES approval_requests(id),
  proposal_id TEXT NOT NULL UNIQUE REFERENCES proposals(id),
  bound_by TEXT NOT NULL CHECK (length(bound_by) BETWEEN 2 AND 120),
  bound_at TEXT NOT NULL,
  UNIQUE (remediation_id, retest_run_id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_direct_retest_record
  ON remediation_direct_retest_bindings(remediation_id, request_id);

CREATE TRIGGER IF NOT EXISTS remediation_direct_retest_insert_guard
BEFORE INSERT ON remediation_direct_retest_bindings
WHEN NOT EXISTS (
  SELECT 1
  FROM remediation_records record
  JOIN remediation_events request_event
    ON request_event.remediation_id = record.id
   AND request_event.event_type = 'retest-requested'
   AND json_extract(request_event.payload_json, '$.requestId') = NEW.request_id
  JOIN runs parent
    ON parent.id = NEW.parent_run_id
   AND parent.mission_id = record.mission_id
   AND parent.status = 'succeeded'
  JOIN runs retest
    ON retest.id = NEW.retest_run_id
   AND retest.mission_id = record.mission_id
   AND retest.parent_run_id = parent.id
   AND retest.lineage_type = 'retest'
   AND retest.status = 'awaiting_approval'
  JOIN proposals proposal
    ON proposal.id = NEW.proposal_id
   AND proposal.run_id = retest.id
   AND proposal.mission_id = record.mission_id
  JOIN approval_requests approval
    ON approval.id = NEW.approval_id
   AND approval.proposal_id = proposal.id
   AND approval.status = 'pending'
  WHERE record.id = NEW.remediation_id
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_DIRECT_RETEST_BINDING_INVALID');
END;

CREATE TRIGGER IF NOT EXISTS remediation_fix_evidence_not_finding_guard
BEFORE INSERT ON remediation_evidence_links
WHEN NEW.purpose = 'fix'
 AND EXISTS (
  SELECT 1
  FROM remediation_events event
  JOIN remediation_records record ON record.id = event.remediation_id
  JOIN finding_revisions revision ON revision.finding_id = record.finding_id
  JOIN finding_evidence_observations citation
    ON citation.finding_revision_id = revision.id
   AND citation.artifact_id = NEW.artifact_id
  WHERE event.id = NEW.remediation_event_id
)
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_FIX_EVIDENCE_REUSES_FINDING');
END;

CREATE TRIGGER IF NOT EXISTS remediation_direct_retest_evidence_guard
BEFORE INSERT ON remediation_evidence_links
WHEN NEW.purpose = 'retest'
 AND EXISTS (
  SELECT 1
  FROM remediation_events event
  JOIN remediation_records record ON record.id = event.remediation_id
  JOIN finding_revisions revision ON revision.finding_id = record.finding_id
  JOIN finding_evidence_observations citation ON citation.finding_revision_id = revision.id
  JOIN evidence_observations source_observation ON source_observation.id = citation.observation_id
  WHERE event.id = NEW.remediation_event_id
    AND source_observation.run_id IS NOT NULL
 )
 AND NOT EXISTS (
  SELECT 1
  FROM remediation_events outcome_event
  JOIN remediation_direct_retest_bindings binding
    ON binding.remediation_id = outcome_event.remediation_id
   AND binding.request_id = json_extract(outcome_event.payload_json, '$.requestId')
  JOIN evidence_observations observation
    ON observation.id = NEW.observation_id
   AND observation.artifact_id = NEW.artifact_id
   AND observation.run_id = binding.retest_run_id
  WHERE outcome_event.id = NEW.remediation_event_id
 )
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_DIRECT_RETEST_EVIDENCE_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS remediation_direct_retest_bindings_immutable_update
BEFORE UPDATE ON remediation_direct_retest_bindings
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_DIRECT_RETEST_BINDING_IMMUTABLE');
END;

CREATE TRIGGER IF NOT EXISTS remediation_direct_retest_bindings_immutable_delete
BEFORE DELETE ON remediation_direct_retest_bindings
BEGIN
  SELECT RAISE(ABORT, 'REMEDIATION_DIRECT_RETEST_BINDING_IMMUTABLE');
END;
