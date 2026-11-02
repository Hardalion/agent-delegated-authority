# Deployment

Operator notes for running the reference packages. This repository does not deploy them for you, and these notes are not a production certificate.

ADAP in this repository is a protocol, reference libraries, and reference adapters. A deployment runs a gateway process that imports `adap`, `adap-store-postgres`, and `adap-gateway`. The agent process is not the authority kernel.

## Minimum shape

1. PostgreSQL 16+ reachable only from gateway subnets.
2. One or more gateway replicas sharing `ADAP_PG_URL`.
3. Vault/KMS for rail credentials (outside this repo).
4. Private network path from gateway → downstream `writeUrl`.
5. Agents can reach only the gateway, with signing keys only.

## Steps

```bash
# 1. Provision Postgres and set ADAP_PG_URL (placeholder values only)
export ADAP_PG_URL=postgresql://adap:CHANGEME@db:5432/adap

# 2. Migrate
pnpm --filter adap-store-postgres build
pnpm --filter adap-store-postgres migrate

# 3. Publish policies via PostgresPolicyRegistry.registerAsync (operator job)

# 4. Run gateway replicas with the same ADAP_PG_URL and vault-backed CredentialBroker

# 5. Readiness: SELECT 1 against Postgres; reject traffic if store unavailable
```

## Rollback

```bash
# Application: redeploy previous gateway image; do not skip nonce store.
# Schema: only if no production nonces must be retained
node packages/adap-store-postgres/dist/migrate-cli.js down
# Prefer forward-fix migrations in real environments.
```

## Non-goals

This document does not create cloud resources. Do not deploy to customer production without explicit authorization.
