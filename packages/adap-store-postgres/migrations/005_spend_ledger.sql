-- Durable cumulative spend accounting (#46).
--
-- One row per (delegation, pool, intent). A pool is identified by
-- (tenant_id, delegation_id, field, currency, ceiling), matching the key in
-- MemorySpendLedger. The running total is SUM(amount) for that pool; it is
-- checked against `ceiling` inside the charging transaction, never by a
-- read-then-write outside it.
--
-- Rows are immutable. A retry of the same intent inserts nothing, so a
-- transient retry cannot double-charge. Rows are retained for the lifetime of
-- the delegation; do not delete them while the delegation can still be
-- presented.
--
-- Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS adap_spend (
  tenant_id TEXT NOT NULL DEFAULT 'default',
  delegation_id TEXT NOT NULL,
  field TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT '',
  ceiling BIGINT NOT NULL,
  amount BIGINT NOT NULL,
  intent_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, delegation_id, field, currency, intent_hash),
  CONSTRAINT adap_spend_ceiling_nonnegative CHECK (ceiling >= 0),
  CONSTRAINT adap_spend_amount_nonnegative CHECK (amount >= 0),
  CONSTRAINT adap_spend_field_format CHECK (field ~ '^[A-Za-z][A-Za-z0-9_]*$'),
  CONSTRAINT adap_spend_currency_format CHECK (currency = '' OR currency ~ '^[A-Z]{3}$'),
  CONSTRAINT adap_spend_intent_nonempty CHECK (char_length(intent_hash) > 0)
);

CREATE INDEX IF NOT EXISTS adap_spend_pool_idx
  ON adap_spend (tenant_id, delegation_id, field, currency, ceiling);

INSERT INTO adap_schema_migrations (id)
VALUES ('005_spend_ledger')
ON CONFLICT (id) DO NOTHING;

COMMIT;
