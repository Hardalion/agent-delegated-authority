# ADAP documentation

ADAP is an open protocol. This repository also contains reference implementations. A package, a local Compose drill, and a passing test are not a production deployment and not a certification.

| Path | What it is |
| --- | --- |
| [spec/](../spec/) | Protocol requirements |
| [docs/architecture/reference.md](architecture/reference.md) | How the reference packages relate to the protocol |
| [docs/security/status.md](security/status.md) | Current security status of this tree |
| [docs/security/regression-matrix.md](security/regression-matrix.md) | ADAP-001 through ADAP-011 and the tests that cover them |
| [docs/operations/local-staging.md](operations/local-staging.md) | Local Compose drill |
| [docs/operations/outcome-unknown.md](operations/outcome-unknown.md) | Reference-gateway unknown outcome and reconciliation |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | What this draft does and does not guarantee |

## Historical records

Earlier historical material — internal readiness snapshots, staging drill reports, audit remediation notes, and operator runbooks under `docs/*/historical/` and `docs/operations/` — is no longer maintained in the public tree. This repository keeps what is needed to understand and implement the protocol: the [spec/](../spec/) requirements, the reference packages, their tests, and the current security documents above.

Removing a historical document is not a statement that anything in it was resolved. Open findings and residual limitations remain described in [docs/security/status.md](security/status.md), [docs/security/regression-matrix.md](security/regression-matrix.md), and [docs/security/residual-risks.md]. Those files remain the authoritative public security record. Nothing here became secret: previous versions of the removed documents remain in this repository's public Git history.
