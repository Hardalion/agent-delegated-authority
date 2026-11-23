BEGIN;

DROP TABLE IF EXISTS adap_revoked_grants;

DELETE FROM adap_schema_migrations WHERE id = '004_revoked_grants';

COMMIT;
