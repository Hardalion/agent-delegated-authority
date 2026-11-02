# STAGING-ARCHITECTURE

Local staging only. No cloud account. No production deploy.

Project name: `adap-staging`. Compose file: `staging/docker-compose.yml`.

```
agent (edge network only)
    |  HTTPS + gateway client token
    v
gateway-a     gateway-b          edge + trust
    |              |
    +------+-------+
           | trust network
           v
     PostgreSQL 16     Vault 1.18.5 (dev mode)     downstream     alert-sink
```

| Piece | What it is |
| --- | --- |
| `gateway-a`, `gateway-b` | Two processes of `packages/adap-gateway/dist/server.js`. Shared `ADAP_PG_URL`. TLS on port 8443 inside the network. |
| `postgres` | Postgres 16, volume `pgdata`, `max_connections=40`. Published only on `127.0.0.1:55433`. |
| `vault` | HashiCorp Vault server in dev mode. Rail token is written to KV v2 `secret/data/adap/rail`. Gateways and downstream receive a read-only Vault token, not the root token. |
| `downstream` | HTTP write API on the trust network. Not published to the host. Idempotent on intent hash. |
| `alert-sink` | Receives webhook POSTs for critical security events. |
| `agent` | `curl` container on the edge network only. Used to prove it cannot reach downstream or Vault. |

## Trust boundaries that this topology actually enforces

- The agent container is not attached to the trust network. `curl` to `downstream:8080` and `vault:8200` fails.
- The rail bearer token is stored in Vault. Gateway HTTP responses and the captured logs did not contain it.
- Both gateways share one Postgres primary. There is no second writable primary. This topology does not provide split-brain protection.

## What this is not

- Vault dev mode is in-memory. Recreating the Vault container loses the secret until `staging/bootstrap-vault.mjs` runs again.
- The gateway client token is a shared bearer generated into `staging/.env`, which is gitignored. It is not mTLS.
- An agent that is placed on the trust network, or that is given the rail token out of band, is outside this proof.
