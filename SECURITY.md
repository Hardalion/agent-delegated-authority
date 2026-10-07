# Security

Report a vulnerability in this repository through GitHub private vulnerability reporting, or by email to the maintainers listed on the Hardalion organization.

Do not open a public issue that includes a secret, a private key, or customer data.

## What belongs here

This repository is a protocol and a reference implementation. Examples are synthetic. `resource/example`, `prn_example`, `agt_a`, and `agt_b` are fixtures.

Do not commit API keys, tokens, private keys, customer identifiers, private URLs, or production configuration.

Commits reachable from `main` were scanned for API keys, private keys, bearer tokens, customer identifiers, and customer records. None were found. Objects that are no longer on `main` may remain readable by commit id until the host garbage-collects them. That wider scan found no private keys and no customer records. Published receipts are signed. The private keys that produced those signatures are not in this repository. Verification uses the published public keys.
