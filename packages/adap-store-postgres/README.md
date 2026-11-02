# adap-store-postgres

PostgreSQL adapters for ADAP production deployments:

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

Isolation assumption: **READ COMMITTED** with single-statement conditional writes.

## Migrate

```bash
export ADAP_PG_URL=postgresql://adap:adap@127.0.0.1:55432/adap
pnpm --filter adap-store-postgres build
pnpm --filter adap-store-postgres migrate
```

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
