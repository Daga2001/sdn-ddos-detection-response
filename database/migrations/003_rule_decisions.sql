-- The packet-rate rule arm logs its decisions too: detection_decisions.detector may
-- be 'rule' besides 'llm' and 'entropy'. Safe to re-apply; no rows are touched.
BEGIN;
ALTER TABLE detection_decisions
    DROP CONSTRAINT IF EXISTS detection_decisions_detector_check;
ALTER TABLE detection_decisions
    ADD CONSTRAINT detection_decisions_detector_check
    CHECK (detector IN ('llm', 'rule', 'entropy'));
COMMIT;
