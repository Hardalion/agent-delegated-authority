# PRODUCTION-TEST-REPORT

## Environment

- OS: Windows 10 (host)
- Node: workspace engines `>=22`
- PostgreSQL: Docker `postgres:16-alpine` as `adap-pg-prod` on `127.0.0.1:55432`
- `ADAP_PG_URL=postgresql://adap:adap@127.0.0.1:55432/adap`
- `ADAP_PG_FORCE=1`

## Commands and results (this session)

### Build

```
pnpm install
pnpm --filter adap build
pnpm --filter adap-store-postgres build
pnpm --filter adap-gateway build
```

Result: **PASS**

### PostgreSQL integration

```
pnpm --filter adap-store-postgres test:integration
```

Result: **9 passed | 1 skipped** (skip = “NOT EXECUTED” marker suite when PG is available)

Covered:

- Concurrent CAS insert (one winner)
- Concurrent claim (one winner)
- Restart persistence of consumed nonce
- Pending restart + mismatched continuation + one-shot approve
- Failed CAS leaves prior version
- DB down fail-closed
- Tenant isolation
- Multi-instance `runAuthorityPath` single execute
- Policy registry first-hash-wins + revoke

### Gateway

```
pnpm --filter adap-gateway test
```

Result: **7 passed**

### Full store package (after serializing shared-database tests)

An earlier combined run failed 3 tests because Vitest executed both files in parallel and `TRUNCATE` raced with in-flight CAS. The suite now sets `fileParallelism: false`. Statement timeout is applied on the connection string, not with a racing `SET` on `connect`.

```
pnpm --filter adap-store-postgres test
```

Result: **13 passed | 1 skipped** (the skip is the “NOT EXECUTED” marker, which only runs when Postgres is absent).

Covered in addition to the integration list above:

- Connection refusal fails closed
- `statement_timeout` cancels `pg_sleep`
- Idempotent consume, then claim rejected
- Concurrent `markApproved`: one winner

### Security suite

```
pnpm test:security
```

Result: **PASS**

| Package | Tests |
| --- | --- |
| adap-policy fail-closed | 11 |
| adap adversarial + RT + final + production | 63 |
| adap-receipt security semantics | 3 |
| adap-gateway | 7 |

### Other

```
pnpm typecheck
pnpm audit --audit-level high
pnpm bench
```

Typecheck: **PASS**. Audit high: **no known vulnerabilities**. Bench (in-process, n=200 after 50 warm-up): sign+verify mean 0.133 ms; policy hash mean 0.008 ms; full ALLOW path mean 0.490 ms. This is not a Postgres contention or staging load test.

## Integration tests actually executed

Yes — against real PostgreSQL 16 in Docker, not an in-memory mock.

## Not executed

- Staging deployment
- Vault-backed broker
- External security retest
- Full DR restore drill
- Multi-region Postgres failover
