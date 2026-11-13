# Threat model

**Status:** Public Draft (v0.1).  
**License:** Apache 2.0

This document is the protocol-level threat model for the ADAP public draft.

ADAP defines delegated-authority semantics. It does not by itself prevent:

- An agent process that ignores a policy decision and calls a tool anyway.
- Stolen signing keys or leaked credentials.
- A resource server that acts without verifying a receipt.
- Deployment mistakes that place production credentials inside the agent runtime.

A passing reference test is not a production security certification. See also [conformance.md](./conformance.md) and [execution.md](./execution.md).
