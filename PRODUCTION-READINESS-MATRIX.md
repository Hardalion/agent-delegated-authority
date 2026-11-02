# PRODUCTION-READINESS-MATRIX

Statuses: `PASS` | `FAIL` | `NOT IMPLEMENTED` | `NOT TESTED` | `BLOCKED BY EXTERNAL DEPENDENCY`

Release check on 2026-11-02. The original assessment PDF is not in this repository. External retest is not complete. Staging gates 1–9 were repeated the same day with `node staging/scripts/run-validation.mjs` (37 passed, exit 0). That drill is local Compose, not a production deployment. Connection exhaustion still allowed `executed: true` on a gateway that already held a connection. This matrix is not a production certification.

| # | Gate | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Original security findings remediated (ADAP-001–011, RT-01/03/04/06/08/10) | PASS for the named tests | `pnpm test:security`, `pnpm attacks`, `node scripts/reproduce-findings.mjs`, `node scripts/redteam-probe.mjs` on 2026-11-02. PDF not in repo. External retest not done |
| 2 | Independent adversarial regression suite | PASS | `pnpm test:security` on 2026-11-02, including `production-adversarial.test.ts` |
| 3 | Real PostgreSQL shared nonce integration tests | PASS | `pnpm test:integration:postgres` with `ADAP_PG_FORCE=1` on 2026-11-02: 13 passed, 1 skipped (`NOT EXECUTED` marker only) |
| 4 | Multi-instance concurrent replay test | PASS | Concurrent CAS + dual `runAuthorityPath` against shared DB |
| 5 | Crash/restart persistence test | PASS | Consume then new pool `assertUsable` rejects |
| 6 | Credential isolation architecture implemented and tested | PASS for this staging topology | Vault dev mode plus edge/trust networks. See `CREDENTIAL-ISOLATION-VALIDATION.md`. Not a production vault |
| 7 | Cryptographically verified identity boundary | PASS (interface) | `StaticIdentityDirectory` tests; not a full IdP |
| 8 | Immutable policy versioning | PASS | Memory + Postgres registry first-hash-wins + revoke |
| 9 | Secure human approval lifecycle | PASS (reference) | Prior RT/final tests + durable pending store |
| 10 | Honest execution and receipt semantics | PASS (partial) | Gateway distinguishes unknown/failed; full receipt rotation NOT TESTED in staging |
| 11 | Cross-tenant isolation | PASS (store namespace) | Tenant PK tests; protocol is not a multi-tenant SaaS |
| 12 | Dependency and supply-chain security | PASS (local) | `pnpm audit --audit-level high` on 2026-11-02: no known vulnerabilities. CI runs the same audit. GitHub Actions itself was not observed in this session |
| 13 | Observability and incident response | PASS for three alerts | Alert sink received `replay.attempt`, `execution.outcome_unknown`, `storage.failure` |
| 14 | Backup and restore verification | PASS | Staging `pg_dump` 285 ms, restore 381 ms. See `BACKUP-RESTORE-DRILL.md` |
| 15 | Staging deployment verification | PASS for the local drill | Re-run 2026-11-02: `node staging/scripts/run-validation.mjs`, 37 passed, exit 0. Not a production deployment |
| 16 | Load and reliability testing | PASS for the stated workload | 33 unique intents, p99 91 ms. Not a production capacity test |
| 17 | External independent security retest | BLOCKED BY EXTERNAL DEPENDENCY | Package prepared. No reviewer report |
| 18 | Documented residual risks and operational ownership | PASS | `PRODUCTION-RESIDUAL-RISKS.md` |

## Staging acceptance gates

Statuses for this section: `PASS`, `FAIL`, `NOT TESTED`, `BLOCKED BY EXTERNAL DEPENDENCY`.

| # | Gate | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Staging deployment works | PASS | Both gateways ready on Postgres 16 |
| 2 | Two replicas coordinate through PostgreSQL | PASS | Shared `adap_nonces` row `consumed` |
| 3 | Concurrent replay has one winner | PASS | One `executed: true`, one `BLOCK`, one downstream write |
| 4 | Credential isolation by secret manager and network | PASS | Vault KV plus agent curl exit 6. Dev-mode Vault, not production HA |
| 5 | Backup and restore | PASS | Dump 285 ms, restore 381 ms, consumed nonce restored |
| 6 | Pending approvals survive restart | PASS | Row still `pending` after both gateways restarted |
| 7 | Outcome-unknown is safe | PASS | Retry `BLOCK`, reconcile found one downstream record |
| 8 | Load testing | PASS | 33/33, p99 91 ms, threshold 2000 ms on this host |
| 9 | Critical alerts verified | PASS | `replay.attempt`, `execution.outcome_unknown`, `storage.failure` hit the sink |
| 10 | External security retest | NOT TESTED | `EXTERNAL-RETEST-PACKAGE.md` only |

## Decision

Staging gates 1–9 passed on this host. Gate 10 has no reviewer report.

This matrix does not authorize a production cutover. Connection exhaustion did not stop a gateway that already held a database connection (`executed: true` while new clients received `sorry, too many clients already`). One Postgres primary. No split-brain control.
