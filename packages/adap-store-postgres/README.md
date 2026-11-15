# adap-store-postgres

PostgreSQL adapters for a deployment of the ADAP reference path. They are not a hosted database and not a certification.

- `PostgresAtomicNonceBackend` — durable `AsyncAtomicNonceBackend` for `SharedNonceLedger`
- `PostgresPendingStore` — durable pending REQUIRE_HUMAN context
- `PostgresPolicyRegistry` — immutable policy publication with revoke

## Guarantees

| Property | Mechanism |
| --- | --- |
| Single insert winner | `PRIMARY KEY (tenant_id, nonce)` + `ON CONFLICT DO NOTHING` |
| Versioned CAS | `UPDATE … WHERE version = $expected RETURNING` |
| Restart durability | Rows are never deleted by the adapter |
| Fail closed | Rejected queries propagate; the authority path must not execute |

Isolation assumption: **READ COMMITTED** with single-statement conditional writes. The compare-and-swap is one claim per nonce in that database. It is not exactly-once delivery across an external system.

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

Without a live PostgreSQL, do not claim distributed replay protection is verified.
