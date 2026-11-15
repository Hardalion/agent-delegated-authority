# Authority

**Status:** Public Draft (v0.1).

Authority says who may attempt an action. Policy says whether that action is permitted. A receipt records what was decided and whether anything executed. A runtime is where an authorization decision becomes an execution boundary. Any implementation can supply that runtime. A production runtime is implementation-defined.

The protocol does not require a particular vendor, a language model, an agent framework, a centralized registry, or a particular transport.

Delegation, intent, and receipt semantics do not require Ed25519, SHA-256, or a particular canonicalization. Those algorithms are the reference profile in this repository. Another profile is conforming when it preserves the bindings and states its algorithms.

## Identity

Agent identity is implementation-independent. This draft treats an agent id as an opaque string. This specification does not define an identity namespace, a registry, or a hosted directory.

An id is not a credential.

## Primitives

| Primitive | Specification |
| --- | --- |
| Delegation | [delegation.md](./delegation.md) |
| Intent | [intent.md](./intent.md) |
| Policy decision | [policy-decision.md](./policy-decision.md) |
| Human approval | [human-approval.md](./human-approval.md) |
| Authorization receipt | [authorization-receipt.md](./authorization-receipt.md) |
| Execution boundary | [execution.md](./execution.md) |
| Conformance | [conformance.md](./conformance.md) |

## Reference

`packages/aap` is one reference path. The caller supplies the signing identity and the execution callback. `BLOCK` does not call the executor.
