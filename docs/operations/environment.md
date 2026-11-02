# Environment

Placeholders only. Never commit real secrets. Variables below are the ones this repository reads. Names that are absent here are not configuration.

| Variable | Read by | Purpose |
| --- | --- | --- |
| `ADAP_PG_URL` | `adap-store-postgres` migrate CLI, gateway, integration tests | PostgreSQL connection string |
| `ADAP_PG_FORCE` | integration tests only | Run those tests against the local fixture URL when `ADAP_PG_URL` is unset |
| `ADAP_REPLICA_ID` | `adap-gateway` server | Replica label. Default `gateway` |
| `PORT` | `adap-gateway` server | Listen port. Default `8443` |
| `ADAP_DIRECTORY_PATH` | `adap-gateway` server | JSON identity directory |
| `ADAP_ISSUER_KEY_PATH` | `adap-gateway` server | Ed25519 issuer private key file |
| `ADAP_GATEWAY_CLIENT_TOKEN` | `adap-gateway` server | Bearer token the gateway expects from its caller |
| `ADAP_ALERT_WEBHOOK` | `adap-gateway` server | Optional alert URL |
| `ADAP_DOWNSTREAM_ALLOWLIST` | staging compose, passed into the process environment | Prefix the reference broker accepts for `writeUrl` |
| `VAULT_ADDR` | `adap-gateway` server | Vault address for the readiness check. Default is a non-routable local placeholder |
| `VAULT_SECRET_PATH` | `adap-gateway` server | KV path. Default `secret/data/adap/rail` |
| `TLS_CERT_PATH` | `adap-gateway` server | TLS certificate file |
| `TLS_KEY_PATH` | staging compose | TLS private key file mounted for the gateway |
| `ADAP_BENCH_N` | `scripts/benchmark-adap.mjs` | Benchmark iterations. Default `200` |

Tenant id is a constructor option on the Postgres adapters (`tenantId`, default `default`). There is no `ADAP_TENANT_ID` variable.

These names are not read by the code: `ADAP_RECEIPT_ISSUER_KEY`, `ADAP_VAULT_ADDR`, `ADAP_DOWNSTREAM_TIMEOUT_MS`, `ADAP_LOG_LEVEL`.

## Clock

Gateway hosts should use NTP. The reference path rejects a caller-supplied `now`. Expiry skew tolerance is zero.
