# adap-gateway

Reference execution gateway. It is a deployment of the ADAP authority path, not a protocol requirement and not a production certificate.

## Boundary

- Agents present signed intents to the gateway.
- `executeAuthorized` runs `runAuthorityPath` then a credential broker.
- Rail credentials never leave the broker; agents never receive them.
- Downstream outcomes distinguish `completed`, `accepted`, `failed`, and `unknown`.
- `unknown` returns from the executor callback. The authority path then reports `executed: true` and consumes the nonce. `executionState: unknown` is the gateway's statement that the downstream result was not observed. It is not proof the external system committed. A later reconcile read does not POST. See [docs/operations/outcome-unknown.md](../../docs/operations/outcome-unknown.md).

## Production blocker (deployment)

This package alone does not prevent an agent from calling a downstream system if the agent already holds rail credentials or network path to the write URL. Credential isolation is a **deployment property**: vault + private networking + no agent credentials.

## Identity

`StaticIdentityDirectory` verifies key status, algorithm (Ed25519 only), expiry, issuer/audience, and human vs workload kind. It is not an IdP.
