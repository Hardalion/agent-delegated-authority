# STAGING-SECURITY-TESTS

Executed by `staging/scripts/run-validation.mjs` against two gateway containers and Postgres 16. These are not in-process objects.

## Replay

The same signed intent was posted at the same time to `127.0.0.1:8443` and `127.0.0.1:8444`.

- Decisions: `ALLOW` and `BLOCK`
- Executed: `true` and `false`
- `adap_nonces.status` for that nonce: `consumed`, `in_flight` false
- Downstream `businessWrites`: 1
- Alert sink received `replay.attempt`

## Human approval

First call with policy `staging-human@1` returned `REQUIRE_HUMAN`. Both gateway containers were restarted. The pending row was still `pending`. The same approval was then posted to both replicas.

- Executed: one `true`, one `false`
- Decisions: `ALLOW` and `BLOCK`

## Direct access from the agent network

The `agent` service is attached only to the `edge` network.

| Attempt | Result |
| --- | --- |
| `https://gateway-a:8443/healthz` with the staging CA | HTTP 200 |
| `POST /v1/authorize` with no client token | HTTP 401 |
| `http://downstream:8080/write` | curl exit 6 |
| `http://vault:8200/v1/sys/health` | curl exit 6 |

Exit 6 is curl's "could not resolve host". The names exist only on the trust network.

## Credential handling

- Rail token lives in Vault KV `secret/data/adap/rail`.
- Gateway JSON bodies did not contain that token.
- `docker compose logs` for the gateways and downstream did not contain the rail token, the gateway client token, or the Vault root token.
- After the secret was replaced, a probe with the old token got `401`. A probe with the new token got `200`. A new intent then executed.

Vault is the official `hashicorp/vault:1.18.5` image in dev mode. Dev mode is not a durable or highly available secret manager.
