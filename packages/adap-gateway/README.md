# adap-gateway

Reference execution gateway. It is a deployment of the ADAP authority path, not a protocol requirement and not a production certificate.

## Boundary

- Agents present signed intents to the gateway.
- `executeAuthorized` runs `runAuthorityPath` then a credential broker.
- Rail credentials never leave the broker; agents never receive them.
- Downstream outcomes distinguish `completed`, `accepted`, `failed`, and `unknown`.
- `unknown` returns from the executor callback as `{ executionState: 'unknown' }`. The authority path keeps `ALLOW`, sets `execution.executed` to false, and consumes the nonce. That is not proof the external system committed, and it is not a claim that the effect was prevented. A later reconcile read does not POST. See [docs/operations/outcome-unknown.md](../../docs/operations/outcome-unknown.md).

## Production blocker (deployment)

This package alone does not prevent an agent from calling a downstream system if the agent already holds rail credentials or network path to the write URL. Credential isolation is a **deployment property**: vault + private networking + no agent credentials.

## Identity

`StaticIdentityDirectory` verifies key status, algorithm (Ed25519 only), expiry, issuer/audience, and human vs workload kind. It is not an IdP.
