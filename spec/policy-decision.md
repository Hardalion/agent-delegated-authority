# Policy decision

Policy says what an agent is allowed to do.

A conforming evaluator returns one of:

| Action | Meaning |
| --- | --- |
| `ALLOW` | The policy permits the attempt |
| `BLOCK` | The policy refuses the attempt. Nothing executes |
| `REQUIRE_HUMAN` | A person must approve before execution |

`DEFER` and `SIMULATE` are not v0.1 decisions. The schema rejects them. They must not reach an executor. Receipt records may still contain those verbs; a receipt verb is not a policy action. See [policy-schema.md](./policy-schema.md).

The same policy, tool, and arguments yield the same `action` and `ruleId`. See [deterministic-evaluation.md](./deterministic-evaluation.md) and [policy-schema.md](./policy-schema.md).

A policy pin is `{policy-id}@{semver}`. The URI scheme is implementation-defined. See [policy-federation.md](./policy-federation.md).

`BLOCK` cannot be overridden by a later approval. A policy cap that is tighter than a delegation still blocks.

## Which policy governs

`policyUri` must name a document the operator already registered. Caller-supplied policy bytes are not authoritative unless they hash to that pin.

When more than one policy is registered, a conforming deployment MUST NOT let an unauthenticated client alone choose a weaker policy. Prefer one of:

1. A required `policy` pin on the root delegation (a child may name a stricter pin but must not drop or replace it with an unrelated one).
2. Operator configuration keyed by target namespace.

The reference gateway may still accept `x-adap-policy-uri` for local drills. Production deployments that claim ADAP enforcement resolve the governing policy from the chain or operator config, then verify the presented document hash.

## Reference

`packages/policy-engine` is a reference evaluator. It is not required to conform. `packages/aap` `ImmutablePolicyResolver` is the reference pin store.
