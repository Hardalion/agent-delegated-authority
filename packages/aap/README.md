# ADAP

Reference implementation of this draft. Not normative. Not a commercial runtime. Ed25519, SHA-256, and canonical JSON are the reference profile. They are not the protocol.

Delegation says who may act. An intent says what the agent is attempting. Policy says what may happen. A receipt records what was authorized and whether the runtime reported execution. The signature verifies when the caller holds the issuer public key. Runtime is implementation-defined. This package is not a hosted runtime. The caller supplies the signing identity and the execution callback.

```
Principal → Agent A → Agent B → Authorized action → Receipt
```

`runAuthorityPath` verifies the delegation chain and the signed intent, evaluates the policy, and emits an Authorization Receipt. `BLOCK` does not call the executor.

The reference walkthrough is synthetic. A principal delegates to Agent A. Agent A may pass `read` to Agent B. `apply` stays with Agent A and waits for the principal. Identifiers `prn_example`, `agt_a`, `agt_b`, and `resource/example` are not organizations. The example policy is `examples/policies/basic-agent-authority.yaml`.
