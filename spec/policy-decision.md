# Policy decision

Policy says what an agent is allowed to do.

A conforming evaluator returns one of:

| Action | Meaning |
| --- | --- |
| `ALLOW` | The policy permits the attempt |
| `BLOCK` | The policy refuses the attempt. Nothing executes |
| `REQUIRE_HUMAN` | A person must approve before execution |

The same policy, tool, and arguments yield the same `action` and `ruleId`. See [deterministic-evaluation.md](./deterministic-evaluation.md) and [policy-schema.md](./policy-schema.md).

A policy pin is `{policy-id}@{semver}`. The URI scheme is implementation-defined. See [policy-federation.md](./policy-federation.md).

`BLOCK` cannot be overridden by a later approval. A policy cap that is tighter than a delegation still blocks.

## Which policy governs (proposed)

> Status: proposed in review.

`policyUri` is a caller input to the reference path, and the reference gateway reads it from the `x-adap-policy-uri` request header. When more than one policy is registered, a client chooses which one evaluates its request. With the staging pair, a client avoids `REQUIRE_HUMAN` by sending the ALLOW policy's URI.

Proposed: the root delegation carries a required `policy` pin. A child may name a stricter pin but may not drop or replace it with an unrelated one. The runtime resolves the governing policy from the chain or from operator configuration keyed by target namespace, never from the request.

## Reference

`packages/policy-engine` is a reference evaluator. It is not required to conform.
