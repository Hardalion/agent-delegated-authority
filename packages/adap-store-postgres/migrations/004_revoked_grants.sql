-- Delegation ids withdrawn before expires_at. The gateway revocation check reads this table.

BEGIN;

CREATE TABLE IF NOT EXISTS adap_revoked_grants (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  delegation_id TEXT NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, delegation_id),
  CONSTRAINT adap_revoked_grants_id_nonempty CHECK (char_length(delegation_id) > 0)
);

INSERT INTO adap_schema_migrations (id)
VALUES ('004_revoked_grants')
ON CONFLICT (id) DO NOTHING;

COMMIT;
