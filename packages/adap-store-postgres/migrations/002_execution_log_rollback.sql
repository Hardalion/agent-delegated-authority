BEGIN;

DROP TABLE IF EXISTS adap_execution_log;
DELETE FROM adap_schema_migrations WHERE id = '002_execution_log';

COMMIT;
