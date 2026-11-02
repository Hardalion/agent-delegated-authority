-- Execution knowledge for downstream reconciliation.
-- This table does not authorize a retry. `unknown` and `started` are not success.

BEGIN;

CREATE TABLE IF NOT EXISTS adap_execution_log (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  intent_hash TEXT NOT NULL,
  nonce TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (
    state IN ('started', 'accepted', 'completed', 'failed', 'unknown', 'reconciled')
  ),
  detail TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, intent_hash)
);

CREATE INDEX IF NOT EXISTS adap_execution_log_state_idx ON adap_execution_log (state);

INSERT INTO adap_schema_migrations (id)
VALUES ('002_execution_log')
ON CONFLICT (id) DO NOTHING;

COMMIT;
