# adap-gateway

Reference execution gateway. It is a deployment of the ADAP authority path, not a protocol requirement and not a production certificate.

## Boundary

The HTTP gateway requires `ADAP_POLICY_BINDINGS_PATH`, pointing to an operator-owned
JSON array of exact `{ principalId, action, target, policyUri }` bindings. For example,
`[{"principalId":"prn_staging","action":"apply","target":"resource/human","policyUri":"staging-human@1"}]`.
All policies must already exist in the registry. Empty, invalid, duplicate, or
unregistered bindings prevent startup. Mount the file read-only and restart all
replicas when changing it. A request without a matching binding is rejected.
The optional `x-adap-policy-uri` header must agree with the selected binding.
The authority path verifies the signatures and signed fields before executing.
Approval continuation also passes this selection and the existing pending-policy
binding checks. A changed mapping therefore fails closed for an old pending intent.
The staging drill uses distinct `resource/example` and `resource/human` targets to
demonstrate ALLOW and REQUIRE_HUMAN under fixed operator bindings.

- Agents present signed intents to the gateway.
- `executeAuthorized` runs `runAuthorityPath` then a credential broker.
- Rail credentials never leave the broker; agents never receive them.
- Downstream outcomes distinguish `completed`, `accepted`, `failed`, and `unknown`.
- `unknown` returns from the executor callback. The authority path then reports `executed: true` and consumes the nonce. `executionState: unknown` is the gateway's statement that the downstream result was not observed. It is not proof the external system committed. A later reconcile read does not POST. See [docs/operations/outcome-unknown.md](../../docs/operations/outcome-unknown.md).
- `executionStatePersistence` is `not_configured`, `not_attempted`, `callback_returned`, `confirmed`, or `failed`. A supplied callback that never runs is `not_attempted`. A callback that returns without `'confirmed'` is `callback_returned`, not proof of durable storage. `confirmed` means every call returned `'confirmed'`. A failed write before the downstream call prevents that call. A failed write after it is reported and the call is not repeated.

## Production blocker (deployment)

This package alone does not prevent an agent from calling a downstream system if the agent already holds rail credentials or network path to the write URL. Credential isolation is a **deployment property**: vault + private networking + no agent credentials.

## Identity

`StaticIdentityDirectory` verifies key status, algorithm (Ed25519 only), expiry, issuer/audience, and human vs workload kind. It is not an IdP.
