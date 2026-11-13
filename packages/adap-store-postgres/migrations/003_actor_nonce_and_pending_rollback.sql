-- Best-effort rollback for 003. Unsafe if actor-scoped rows already exist
-- with the same nonce under different actors (would collide on the old PK).

BEGIN;

ALTER TABLE adap_pending DROP CONSTRAINT IF EXISTS adap_pending_approval_state_check;
ALTER TABLE adap_pending
  ADD CONSTRAINT adap_pending_approval_state_check
  CHECK (approval_state IN ('pending', 'approved', 'consumed'));

ALTER TABLE adap_pending DROP CONSTRAINT IF EXISTS adap_pending_pkey;
ALTER TABLE adap_pending ADD CONSTRAINT adap_pending_pkey PRIMARY KEY (tenant_id, nonce);
ALTER TABLE adap_pending DROP COLUMN IF EXISTS actor_id;

ALTER TABLE adap_nonces DROP CONSTRAINT IF EXISTS adap_nonces_pkey;
ALTER TABLE adap_nonces ADD CONSTRAINT adap_nonces_pkey PRIMARY KEY (tenant_id, nonce);
ALTER TABLE adap_nonces DROP COLUMN IF EXISTS actor_id;

DELETE FROM adap_schema_migrations WHERE id = '003_actor_nonce_and_pending';

COMMIT;
