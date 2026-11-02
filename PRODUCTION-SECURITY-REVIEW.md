# PRODUCTION-SECURITY-REVIEW

## Scope

Hardalion ADAP `npl-spec` on branch `security/adap-complete-remediation`, HEAD `1fa576a8ef4a889685d5623d67c9ae71366c8f2d`, plus uncommitted remediation and this production pass.

## Trust model (actual)

| Layer | Guarantees |
| --- | --- |
| Protocol | Narrowing, binding, amount/target rules when inputs are validated |
| Reference `adap` | In-process fail-closed path |
| `adap-store-postgres` | Cross-process nonce/pending exclusion when all instances share one DB |
| `adap-gateway` | Credential broker boundary in-process; deployment must deny agent→rail paths |
| Deployment | Vault, TLS, network segmentation, backups — outside repo |

## Findings addressed in this pass

| ID | Topic | Result |
| --- | --- | --- |
| PROD-01 | Distributed replay only via test double | **Remediated in code + tested on real Postgres 16** |
| PROD-02 | No credential isolation component | **Reference gateway + broker**; deploy still required |
| PROD-03 | Identity only caller-supplied map | **Directory with revoke/expiry/alg checks**; still operator-provisioned keys |
| PROD-04 | Policy not durable | **PostgresPolicyRegistry** |
| PROD-05 | No ops/monitoring docs | **Runbooks + event types** |

## Re-audit notes (ADAP / RT)

Prior remediation tests remain the regression spine. This pass did not weaken assertions. New adversarial cases cover traversal, amount boundary, approval/intent mutation, prototype pollution, and nonce races.

## Residual (see PRODUCTION-RESIDUAL-RISKS.md)

External retest, staging network proof, vault broker, backup drill, load test.
