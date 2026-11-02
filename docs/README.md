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
| [docs/operations/deployment.md](operations/deployment.md) | Deployment assumptions for an operator who runs the reference gateway |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | What this draft does and does not guarantee |

`docs/security/historical/` and `docs/operations/historical/` keep earlier audit notes and drill records. They are labeled historical. Do not read a commit id in those files as the current `main`.
