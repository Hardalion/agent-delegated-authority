# ENVIRONMENT-CONFIGURATION

Placeholders only. Never commit real secrets.

| Variable | Required | Purpose |
| --- | --- | --- |
| `ADAP_PG_URL` | Production gateway | PostgreSQL connection string for nonce/pending/policy |
| `ADAP_PG_FORCE` | Local test only | Force integration tests against default local URL |
| `ADAP_TENANT_ID` | Multi-tenant deploy | Tenant namespace for store adapters (default `default`) |
| `ADAP_RECEIPT_ISSUER_KEY` | Gateway | Path/ref to Ed25519 issuer private key in vault |
| `ADAP_VAULT_ADDR` | Gateway | Vault/KMS endpoint for rail credential handles |
| `ADAP_DOWNSTREAM_TIMEOUT_MS` | Gateway | Downstream POST timeout (default 10000) |
| `ADAP_LOG_LEVEL` | Ops | `info` / `warn` / `error` — never log full payloads by default |
| `ADAP_BENCH_N` | Benchmarks | Measured iterations for `pnpm bench` |

## TLS

Require TLS for Postgres and gateway ingress in staging/production. Terminate TLS at the load balancer or gateway; do not accept plaintext agent traffic on public networks.

## Clock

Gateway hosts must use NTP. Protocol skew tolerance is zero for expiry checks.
