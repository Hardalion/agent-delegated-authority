# Local staging

A Docker Compose drill in this repository. It is not a production deployment, not a customer environment, and not a certification.

## Run

Requirements: Docker, Node 22, pnpm. From a clone of this repository:

```bash
node staging/scripts/run-validation.mjs
```

The script writes gitignored files:

- `staging/.env` — random values for the Postgres password, the Vault dev root token, and the gateway client token
- `staging/.secrets/` — TLS material and public keys used by the drill
- `staging/.evidence/summary.json` — check output

Do not commit those files. The placeholders are in [staging/.env.example](../../staging/.env.example).

Stop and delete the drill volumes:

```bash
docker compose -f staging/docker-compose.yml --project-directory staging down -v
```

## What the compose file runs

Loopback ports from [staging/docker-compose.yml](../../staging/docker-compose.yml):

| Port | Process |
| --- | --- |
| 8443 | gateway-a |
| 8444 | gateway-b |
| 55433 | Postgres 16 |
| 18200 | Vault |
| 9099 | alert sink |

The downstream writer is not published on the host. Two networks separate an `agent` container, which can reach the gateways, from Postgres, Vault, and the downstream writer. That split is a property of this compose file. Copying the images elsewhere does not recreate it.

## Vault dev mode

The drill uses `hashicorp/vault` with `server -dev`.

- Secrets are in memory. A new Vault container is empty until bootstrap runs again.
- The root token is a generated value in the Vault process environment and in gitignored `staging/.env`. It is not AppRole, Shamir unseal, or a production seal.
- Gateways and the downstream process receive a read-only token for the rail path, not the root token.
- This is enough to exercise the reference broker. It is not a production secret manager.

## What a green drill does not mean

A passing `summary.json` means the script's checks passed on that machine. It does not mean:

- the external system committed every `executed: true` result
- connection exhaustion fails closed for a gateway that already holds a database connection (the 2026-11-02 drill did not)
- the deployment is highly available
- an independent security retest was done

Postgres integration tests are separate: `pnpm test:integration:postgres`. They run only when `ADAP_PG_URL` is set or `ADAP_PG_FORCE=1`. The force flag uses the local URL in `packages/adap-store-postgres/src/harness.ts`. That URL is a local fixture, not a credential to reuse.
