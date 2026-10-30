# ADAP

Reference implementation of this draft. Not normative. Not a commercial runtime. Ed25519, SHA-256, and canonical JSON are the reference profile. They are not the protocol.

Delegation says who may act. An intent says what the agent is attempting. Policy says what may happen. A receipt records what was authorized and whether the runtime reported execution. The signature verifies when the caller holds the issuer public key. Runtime is implementation-defined. This package is not a hosted runtime. The caller supplies the signing identity and the execution callback.

```
Principal → Agent A → Agent B → Authorized action → Receipt
```

`runAuthorityPath` verifies the delegation chain and the signed intent, evaluates the policy, and emits an Authorization Receipt. `BLOCK` does not call the executor. On the `ALLOW` path the nonce is claimed exclusively (`claimForExecution`) before `await execution()`, then marked `consumed` or `failed`.

`NonceLedger` is in memory: the claim is exclusive within one process and is lost on restart. Several processes need the same claim in a shared atomic store.

The caller-supplied `execute` callback is for local testing. If the agent process holds the API credential, it can skip this path. Keeping the credential out of the agent process is a deployment property; see [THREAT_MODEL.md](../../THREAT_MODEL.md).

The reference walkthrough is synthetic. A principal delegates to Agent A. Agent A may pass `read` to Agent B. `apply` stays with Agent A and waits for the principal. Identifiers `prn_example`, `agt_a`, `agt_b`, and `resource/example` are not organizations. The example policy is `examples/policies/basic-agent-authority.yaml`.
