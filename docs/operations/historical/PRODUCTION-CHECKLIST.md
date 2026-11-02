> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../../security/status.md).

# PRODUCTION-CHECKLIST

Use before staging validation. Items marked **BLOCKER** prevent a production-ready claim.

## Implementation

- [x] PostgreSQL nonce adapter (`adap-store-postgres`)
- [x] PostgreSQL pending store
- [x] Migrations + rollback SQL
- [x] Real PG multi-instance concurrency tests (executed locally with Docker)
- [x] Crash/restart persistence test (new pool)
- [x] Execution gateway + credential broker interface
- [x] Identity directory with revoke/expiry/algorithm checks
- [x] Policy registry persistence + revoke
- [x] Security event sink
- [x] Security CI workflow
- [x] Benchmark script

## Staging (not done in this mission)

- [ ] Staging deploy of gateway replicas
- [ ] Vault-backed broker (not MemoryCredentialBroker)
- [ ] Network isolation proven (agent cannot reach writeUrl)
- [ ] Backup/restore drill
- [ ] Load test against shared Postgres
- [ ] External independent security retest

## Do not claim

- “Production ready” until every mandatory gate in `PRODUCTION-READINESS-MATRIX.md` is PASS.
- Distributed safety from in-memory doubles.
- Credential isolation from repository inspection alone.
