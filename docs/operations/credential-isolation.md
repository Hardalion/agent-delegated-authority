# Credential isolation

Local Compose drill. Vault here is dev mode. This is not a production secret-manager validation.

# CREDENTIAL-ISOLATION-VALIDATION

## What was deployed

HashiCorp Vault `1.18.5` in dev mode, on the trust network only.

`staging/bootstrap-vault.mjs`:

- Writes a random rail token and `writeUrl=http://downstream:8080/write` to `secret/data/adap/rail`.
- Creates ACL policy `adap-read` with `read` on that path only.
- Writes the resulting client token to the bootstrap volume.

Gateway and downstream processes read that token. They do not receive the Vault root token. The root token exists only as `VAULT_DEV_ROOT_TOKEN_ID` on the Vault container and in the gitignored `staging/.env` used by the operator script.

The gateway broker refuses a `writeUrl` that does not start with `http://downstream:8080/`.

## Tests and results

| Test | Result |
| --- | --- |
| Agent container `curl http://downstream:8080/write` | exit 6, name not resolved |
| Agent container `curl http://vault:8200/v1/sys/health` | exit 6, name not resolved |
| Agent `POST /v1/authorize` without the gateway client token | HTTP 401 |
| Authorize response bodies searched for the rail token | not present |
| Gateway and downstream logs searched for rail token, client token, and Vault root | not present |
| Downstream probe with the rail token before rotation | not required for the gate; after rotation the old token returned `401` and the new token returned `200` |
| Authorize of a new intent after rotation | `ALLOW` |

## Limits

- Dev mode keeps secrets in memory. A new Vault container is empty until bootstrap runs again.
- The root token is still present in the Vault process environment. This is not AppRole, not Shamir unseal, and not a production seal.
- Isolation holds for an agent that is only on the edge network and does not possess the rail token. It does not hold if that token or the trust network is given to the agent.
- The gateway client credential is a shared bearer, not a workload certificate.

Credential isolation for this staging topology was exercised. It is not a production vault deployment.
