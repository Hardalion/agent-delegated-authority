-- Rollback for 005_spend_ledger. Destructive: drops recorded cumulative spend.
-- Only safe when no delegation with a cumulative constraint can be presented.

BEGIN;

DROP TABLE IF EXISTS adap_spend;
DELETE FROM adap_schema_migrations WHERE id = '005_spend_ledger';

COMMIT;
