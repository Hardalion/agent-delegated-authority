-- Rollback for 001_adap_store. Destructive: drops production nonce/pending/policy tables.

BEGIN;

DROP TABLE IF EXISTS adap_policies;
DROP TABLE IF EXISTS adap_pending;
DROP TABLE IF EXISTS adap_nonces;
DELETE FROM adap_schema_migrations WHERE id = '001_adap_store';
DROP TABLE IF EXISTS adap_schema_migrations;

COMMIT;
