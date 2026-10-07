# adap-receipt

Offline verifier for Authorization Receipts. No server required.

Apache 2.0. Reference implementation maintained by Hardalion. The package name is not part of the protocol.

## CLI

The package is not currently published to npm. From a clone of this repository, after `pnpm build`:

```bash
node packages/audit-verify/dist/cli.js ./receipt.json --public-key ./issuer-public-key.txt
node packages/audit-verify/dist/cli.js ./receipt.json --verbose
```

With `--public-key`, exit code `0` means structure, content hash, and the Ed25519 signature match. The key file is the issuer SPKI public key, base64url, one line.

Without `--public-key`, exit code `0` means structure and content hash match. The signature was not checked.

## Programmatic

```typescript
import { verifyAuthorizationReceipt, verifyReceiptSignature } from 'adap-receipt'
```

`verifyAuthorizationReceipt` checks structure and the content hash. `verifyReceiptSignature` checks the Ed25519 signature and needs the issuer public key.

Specification: [github.com/hardalion/agent-delegated-authority](https://github.com/hardalion/agent-delegated-authority)
