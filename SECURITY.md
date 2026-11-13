# Security

Report a vulnerability in this repository through GitHub private vulnerability reporting, or by email to the maintainers listed on the Hardalion organization.

Do not open a public issue that includes a secret, a private key, a Team token, or customer data.

This repository is an open protocol draft plus a synthetic hackathon / reference implementation under Apache 2.0. It is not a production security certification and not Hardalion Nexus commercial enforcement infrastructure.

Do not commit API keys, Team tokens, private keys, customer identifiers, private URLs, or production configuration.

Current status, and what is not claimed, is in [docs/security/status.md](docs/security/status.md).

- [docs/security/regression-matrix.md](docs/security/regression-matrix.md) maps ADAP-001 through ADAP-011 to tests
- [docs/security/residual-risks.md](docs/security/residual-risks.md) lists remaining limits
- [THREAT_MODEL.md](THREAT_MODEL.md) is the draft threat model
- Earlier historical audit notes are no longer maintained in the public tree. Previous versions remain in this repository's Git history and do not describe the current tree.

Run `pnpm test` and `pnpm test:security` before merging authority-path changes.

The original assessment PDF is not in this repository. Finding status in the regression matrix is the result of the tests named there, run against the documented attack descriptions. It is not a line-by-line check of that PDF, and it is not an external retest. Mohammad Ali Oweidat's independent retest is not recorded as complete. Staging reports describe a local compose drill. They are not production validation, and this repository does not claim a security certification.

## What belongs here

This repository is a protocol and a reference implementation. Examples are synthetic. `resource/example`, `prn_example`, `agt_a`, and `agt_b` are fixtures. Hackathon Team tokens are for the local event sandbox only.

Commits reachable from the published branches were scanned for API keys, private keys, bearer tokens, customer identifiers, and customer records. None were found. Objects that are no longer on those branches may remain readable by commit id until the host garbage-collects them. Published receipts are signed. The private keys that produced those signatures are not in this repository. Verification uses the published public keys.
