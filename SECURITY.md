# Security

Report a vulnerability in this repository through GitHub private vulnerability reporting, or by email to the maintainers listed on the Hardalion organization.

Do not open a public issue that includes a secret, a private key, or customer data.

## Remediation baseline

Security remediation for findings ADAP-001 through ADAP-011 is documented in:

- [SECURITY-REMEDIATION.md](SECURITY-REMEDIATION.md)
- [SECURITY-VERIFICATION.md](SECURITY-VERIFICATION.md)
- [SECURITY-REGRESSION-MATRIX.md](SECURITY-REGRESSION-MATRIX.md)
- [THREAT_MODEL.md](THREAT_MODEL.md)

Run `pnpm test` and `pnpm test:security` before merging authority-path changes.

The original assessment PDF is not in this repository. Finding status in the regression matrix is the result of the tests named there, run against the documented attack descriptions. It is not a line-by-line check of that PDF, and it is not an external retest. Mohammad Ali Oweidat's independent retest is not recorded as complete. Staging reports describe a local compose drill. They are not production validation, and this repository does not claim a security certification.

## What belongs here

This repository is a protocol and a reference implementation. Examples are synthetic. `resource/example`, `prn_example`, `agt_a`, and `agt_b` are fixtures.

Do not commit API keys, tokens, private keys, customer identifiers, private URLs, or production configuration.

Commits reachable from `main` were scanned for API keys, private keys, bearer tokens, customer identifiers, and customer records. None were found. Objects that are no longer on `main` may remain readable by commit id until the host garbage-collects them. That wider scan found no private keys and no customer records. Published receipts are signed. The private keys that produced those signatures are not in this repository. Verification uses the published public keys.
