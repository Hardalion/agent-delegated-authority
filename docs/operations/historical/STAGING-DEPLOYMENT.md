> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../../security/status.md).

# STAGING-DEPLOYMENT

Local Docker Compose. Do not point this at production.

## Prerequisites

- Docker Desktop with the engine running
- Node 22 and pnpm on the host
- No real customer credentials

## Commands

From `npl-spec`:

```bash
node staging/scripts/run-validation.mjs
```

The script:

1. Writes a gitignored `staging/.env` with random hex values for the Postgres password, the Vault dev root token, and the gateway client token.
2. Generates Ed25519 keys. Only public keys and the gateway issuer key are mounted. Agent private keys stay in the script process.
3. Generates a one-day TLS certificate under `staging/.secrets/tls`.
4. Runs `docker compose down -v` and `docker compose up -d --build` in `staging/`.
5. Executes the checks and writes `staging/.evidence/summary.json`.

Host ports, bound to loopback:

| Port | Service |
| --- | --- |
| 8443 | gateway-a |
| 8444 | gateway-b |
| 55433 | Postgres |
| 18200 | Vault |
| 9099 | alert sink |

Downstream is not published.

## Stop

```bash
docker compose -f staging/docker-compose.yml --project-directory staging down -v
```

`-v` deletes the staging database volume and the Vault bootstrap volume.

## Rollback of the staging database

On a scratch database the drill ran `rollbackMigrations()` from `adap-store-postgres`. After rollback, `adap_nonces`, `adap_pending`, `adap_policies`, `adap_execution_log`, and `adap_schema_migrations` were gone. Re-applying migrations recreates them empty. Do not roll back the live staging database if consumed nonces must be kept.
