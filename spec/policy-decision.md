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

## Reference

`packages/policy-engine` is a reference evaluator. It is not required to conform.
