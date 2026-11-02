-- ADAP production store: nonces, pending approvals, immutable policy registry.
-- Isolation assumption: READ COMMITTED is sufficient because every mutate is a
-- single-statement conditional INSERT/UPDATE that encodes the compare-and-swap.
-- Rows are never deleted while an intent could still be presented.

BEGIN;

CREATE TABLE IF NOT EXISTS adap_schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS adap_nonces (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  nonce TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  status TEXT NOT NULL CHECK (status IN ('pending', 'consumed', 'failed')),
  intent_hash TEXT NOT NULL,
  in_flight BOOLEAN NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, nonce),
  CONSTRAINT adap_nonces_intent_hash_nonempty CHECK (char_length(intent_hash) > 0)
);

CREATE INDEX IF NOT EXISTS adap_nonces_intent_hash_idx ON adap_nonces (intent_hash);

CREATE TABLE IF NOT EXISTS adap_pending (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  nonce TEXT NOT NULL,
  intent_hash TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  delegation_chain_hash TEXT NOT NULL,
  policy_uri TEXT NOT NULL,
  policy_content_hash TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  matched_rule_id TEXT NOT NULL,
  original_decision TEXT NOT NULL CHECK (original_decision = 'REQUIRE_HUMAN'),
  approval_state TEXT NOT NULL CHECK (approval_state IN ('pending', 'approved', 'consumed')),
  expiry TIMESTAMPTZ NOT NULL,
  approver_id TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, nonce),
  CONSTRAINT adap_pending_intent_hash_nonempty CHECK (char_length(intent_hash) > 0)
);

CREATE INDEX IF NOT EXISTS adap_pending_state_idx ON adap_pending (approval_state);

CREATE TABLE IF NOT EXISTS adap_policies (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  content_hash TEXT NOT NULL,
  uri TEXT NOT NULL,
  body JSONB NOT NULL,
  revoked BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, content_hash),
  CONSTRAINT adap_policies_uri_unique UNIQUE (tenant_id, uri)
);

CREATE INDEX IF NOT EXISTS adap_policies_tenant_idx ON adap_policies (tenant_id);

INSERT INTO adap_schema_migrations (id)
VALUES ('001_adap_store')
ON CONFLICT (id) DO NOTHING;

COMMIT;
