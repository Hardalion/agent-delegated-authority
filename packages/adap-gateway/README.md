# adap-gateway

Reference execution gateway for ADAP deployments.

## Boundary

- Agents present signed intents to the gateway.
- `executeAuthorized` runs `runAuthorityPath` then a credential broker.
- Rail credentials never leave the broker; agents never receive them.
- Downstream outcomes distinguish `completed`, `accepted`, `failed`, and `unknown`.

## Production blocker (deployment)

This package alone does not prevent an agent from calling a downstream system if the agent already holds rail credentials or network path to the write URL. Credential isolation is a **deployment property**: vault + private networking + no agent credentials.

## Identity

`StaticIdentityDirectory` verifies key status, algorithm (Ed25519 only), expiry, issuer/audience, and human vs workload kind. It is not an IdP.
