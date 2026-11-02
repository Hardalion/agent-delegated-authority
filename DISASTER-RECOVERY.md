# DISASTER-RECOVERY

## RPO / RTO targets (deployment-defined)

| Data | Suggested RPO | Notes |
| --- | --- | --- |
| `adap_nonces` | Near-zero | Loss can enable replay of consumed nonces — **critical** |
| `adap_pending` | Low | Loss drops open approvals (fail closed) |
| `adap_policies` | Low | Rebuild from operator registry |

## Backup

- Continuous Postgres WAL archiving for the ADAP database.
- Test restore quarterly: restore to staging, run `pnpm test:integration:postgres`.

## Failover

1. Promote Postgres replica.
2. Point all gateways at new primary (`ADAP_PG_URL`).
3. Verify readiness before opening traffic.
4. Never run two writable primaries with divergent nonce tables.

## Restore verification checklist

- [ ] Migrations present (`adap_schema_migrations`)
- [ ] Sample consumed nonce still blocks `assertUsable`
- [ ] Policy hydrate succeeds
- [ ] Gateway readiness green
