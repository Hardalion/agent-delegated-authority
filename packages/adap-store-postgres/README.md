# adap-store-postgres

PostgreSQL adapters for a deployment of the ADAP reference path. They are not a hosted database and not a certification.

- `PostgresAtomicNonceBackend` — durable `AsyncAtomicNonceBackend` for `SharedNonceLedger`
- `PostgresPendingStore` — durable pending REQUIRE_HUMAN context
- `PostgresPolicyRegistry` — immutable policy publication with revoke
- `PostgresSpendLedger` — durable `SpendLedger` for cumulative amount and count constraints

## Guarantees

| Property | Mechanism |
| --- | --- |
| Single insert winner | `PRIMARY KEY (tenant_id, actor_id, nonce)` + `ON CONFLICT DO NOTHING` |
| Versioned CAS | `UPDATE … WHERE version = $expected RETURNING` |
| Actor isolation | Nonce and pending rows keyed by verified `actor_id` |
| Pending queue cap | Transaction + `pg_advisory_xact_lock` + count of active pending |
| Restart durability | Rows are never deleted by the adapter |
| Cumulative budget | `adap_spend` rows summed inside the charging transaction, under `pg_advisory_xact_lock` |
| Atomic charges | One transaction per `spend()`; any rejected charge rolls back the whole call |
| Idempotent intent | Primary key includes `intent_hash`; a replay inserts nothing |
| Fail closed | Rejected queries propagate; the authority path must not execute |

Isolation assumption: **READ COMMITTED** with transactional compare-and-swap and advisory locks for empty queue sets. The compare-and-swap is one claim per `(actor, nonce)` in that database. It is not exactly-once delivery across an external system.

### Migration 003

`migrations/003_actor_nonce_and_pending.sql` adds `actor_id`, replaces primary keys with `(tenant_id, actor_id, nonce)`, expands pending `approval_state` for `declined` / `expired`, and is idempotent. Legacy nonce rows keep `actor_id = ''` as **global tombstones**. The adapter refuses actor-scoped reuse of those nonces for every actor; primary key alone is not sufficient. Tombstones are retained indefinitely (no automatic expiry). Deploy order: migrate, then roll out writers that always set `actor_id` and enforce tombstones. Rollback is not lossless once new actor-scoped rows exist.

### Migration 005

`migrations/005_spend_ledger.sql` adds `adap_spend`, one row per charged intent, keyed by `(tenant_id, delegation_id, field, currency, intent_hash)` with the pool `ceiling` stored alongside the `amount`. Pools are the same key `MemorySpendLedger` uses, so switching a deployment from the in-memory ledger to this adapter preserves budget semantics. Rows are never deleted by the adapter: cumulative spend is charged before execution, so an intent that fails downstream still consumes its budget, and a retried intent is not charged twice. Reusing an intent hash with a different amount, or an existing pool with a different ceiling, is rejected. Rollback drops the table and is lossy.

## Migrate

```bash
export ADAP_PG_URL=postgresql://USER:PASSWORD@127.0.0.1:5432/adap
pnpm --filter adap-store-postgres build
pnpm --filter adap-store-postgres migrate
```

`ADAP_PG_FORCE=1` uses the local fixture URL in `src/harness.ts`. That value is for a database you start yourself. Do not reuse it anywhere else.

Rollback:

```bash
node dist/migrate-cli.js down
```

## Integration tests

```bash
export ADAP_PG_FORCE=1
# or ADAP_PG_URL=...
pnpm --filter adap-store-postgres test:integration
```

Without a live PostgreSQL, do not claim distributed replay protection or cumulative spend enforcement is verified.
