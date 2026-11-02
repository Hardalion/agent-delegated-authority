# BACKUP-RESTORE-DRILL

Logical dump of the staging database `adap` after the replay, approval, and unknown-outcome checks. No production data.

## Commands the script ran

```bash
docker compose exec -T postgres pg_dump -U adap -d adap --no-owner
docker compose exec -T postgres psql -U adap -d postgres -c "DROP DATABASE IF EXISTS adap_restore"
docker compose exec -T postgres psql -U adap -d postgres -c "CREATE DATABASE adap_restore"
docker compose exec -T postgres psql -U adap -d adap_restore -v ON_ERROR_STOP=1
```

The dump was passed on stdin to the restore. A copy is `staging/.evidence/backup.sql` (gitignored).

## Measured times

| Step | Duration |
| --- | --- |
| `pg_dump` | 285 ms |
| Restore into `adap_restore` | 381 ms |

## What was checked after restore

| Row | Restored value |
| --- | --- |
| Nonce used for the two-replica execute | `consumed` |
| Human-approval nonce | `approval_state = consumed` |

The approval row is `consumed` because the approval had already executed before the dump. The earlier restart check, taken before that approval, showed `pending`.

Receipt issuer private key is a file mount (`staging/.secrets/issuer.pem`), not a database row. The dump does not recover it. The drill did not delete that file. Key recovery for a lost issuer key is not demonstrated.

## RPO and RTO for this drill

- RPO: 285 ms. That is the dump duration. Writes that commit after `pg_dump` starts its snapshot are not in this backup.
- RTO: 381 ms. That is the restore duration until `psql` exited 0, on the same host, into an empty database. It does not include provisioning a new machine.

## Rollback drill (separate database)

`adap_drill` was created, migrations applied, then `rollbackMigrations()` ran.

- Before: `adap_execution_log`, `adap_nonces`, `adap_pending`, `adap_policies`, `adap_schema_migrations`
- After: no `adap%` tables

The primary `adap` database was not rolled back.
