# INCIDENT-RESPONSE

## Severity

| Sev | Example |
| --- | --- |
| SEV1 | Suspected double execution across instances |
| SEV2 | Store unavailable / mass BLOCK |
| SEV3 | Elevated signature failures / policy mismatch |

## Double-execution suspicion

1. Freeze gateway deploys.
2. Query `adap_nonces` for the intent hash / nonce.
3. Compare downstream correlation IDs and business ledgers.
4. If two completes for one nonce: treat as deployment bypass (credential leak or split-brain store), not a protocol ALLOW.

## Key compromise

1. Revoke key in identity directory (`status: revoked`).
2. Rotate vault rail credentials.
3. Invalidate pending approvals that named the compromised approver.

## Do not

- Truncate nonce tables to “unblock” traffic.
- Retry non-idempotent downstream calls on `outcome_unknown` with the same nonce.
- Log full customer payloads while debugging in production.
