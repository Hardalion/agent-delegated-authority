-- Actor-scoped nonces (#20) and pending approval enhancements (#21).
-- Additive and idempotent. Does not delete legacy rows.
--
-- Deployment order:
-- 1. Stop writers OR deploy application build that understands both schemas.
-- 2. Apply this migration.
-- 3. Deploy application that always writes actor_id and enforces legacy tombstones.
--
-- Legacy rows keep actor_id = '' as *global nonce tombstones*. The application
-- MUST treat them as blocking reuse of that nonce by any actor (see
-- PostgresAtomicNonceBackend). Primary key alone is not enough: a new
-- (tenant, actor, nonce) row could otherwise coexist with (tenant, '', nonce).
-- Tombstones are retained indefinitely; do not auto-expire them without an
-- explicit replay-protection rule. Rollback is not lossless once new
-- actor-scoped rows exist.

BEGIN;

ALTER TABLE adap_nonces
  ADD COLUMN IF NOT EXISTS actor_id TEXT NOT NULL DEFAULT '';

-- Replace primary key (tenant_id, nonce) with (tenant_id, actor_id, nonce).
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'adap_nonces_pkey'
      AND conrelid = 'adap_nonces'::regclass
  ) THEN
    ALTER TABLE adap_nonces DROP CONSTRAINT adap_nonces_pkey;
  END IF;
END $$;

ALTER TABLE adap_nonces
  ADD CONSTRAINT adap_nonces_pkey PRIMARY KEY (tenant_id, actor_id, nonce);

CREATE INDEX IF NOT EXISTS adap_nonces_actor_idx ON adap_nonces (tenant_id, actor_id);

ALTER TABLE adap_pending
  ADD COLUMN IF NOT EXISTS actor_id TEXT NOT NULL DEFAULT '';

-- Backfill pending actor_id from agent_id for legacy rows.
UPDATE adap_pending
SET actor_id = agent_id
WHERE actor_id = '' OR actor_id IS NULL;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'adap_pending_pkey'
      AND conrelid = 'adap_pending'::regclass
  ) THEN
    ALTER TABLE adap_pending DROP CONSTRAINT adap_pending_pkey;
  END IF;
END $$;

ALTER TABLE adap_pending
  ADD CONSTRAINT adap_pending_pkey PRIMARY KEY (tenant_id, actor_id, nonce);

-- Expand approval_state for DENY / expiry accounting.
ALTER TABLE adap_pending DROP CONSTRAINT IF EXISTS adap_pending_approval_state_check;
ALTER TABLE adap_pending
  ADD CONSTRAINT adap_pending_approval_state_check
  CHECK (approval_state IN ('pending', 'approved', 'declined', 'consumed', 'expired'));

CREATE INDEX IF NOT EXISTS adap_pending_queue_idx
  ON adap_pending (tenant_id, principal_id, agent_id, approval_state, expiry);

INSERT INTO adap_schema_migrations (id)
VALUES ('003_actor_nonce_and_pending')
ON CONFLICT (id) DO NOTHING;

COMMIT;
