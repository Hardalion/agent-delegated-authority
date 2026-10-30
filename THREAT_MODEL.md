# Threat model

**Status:** Public Draft (v0.1).  
**License:** Apache 2.0

ADAP authorization correctness is not complete agent security.

A correct decision means the presented delegation, intent, and policy authorized or refused the action. It does not mean the surrounding system is safe.

The reference path stops these. Nothing else in this list is claimed.

- Over-delegation. A child cannot raise the parent's bound.
- Privilege escalation. A capability marked `delegable: false` cannot be passed on.
- Replay. A nonce is claimed exclusively before execution; a consumed, failed, or in-flight nonce cannot authorize again.
- Unauthorized execution. `BLOCK` and an unresolved `REQUIRE_HUMAN` do not call the executor.
- Prompt injection that tries to raise the bound. Instruction text is not a constraint.

## What this draft guarantees

In the reference path:

| Threat | Result |
| --- | --- |
| Over-delegation | A child that raises `max_amount`, widens a target, outlives the parent, drops a parent constraint, or is issued by anyone other than the parent subject is `BLOCK`. Rule `narrowing`. The executor is not called. |
| Privilege escalation | A capability marked `delegable: false` cannot be passed on. Rule `narrowing`. |
| Unauthorized sub-agent | An action outside the granted capabilities is `BLOCK`. Rule `capability`. |
| Delegation outside the parent scope | Same rules as over-delegation. The child grant is checked against the parent before the intent runs. |
| Expired authority | A delegation or intent outside its lifetime is `BLOCK`. Rule `expired`. |
| Replay / concurrent reuse | The nonce is claimed exclusively (`pending`) before the executor runs, then terminal `consumed` or `failed`. A second claim is `BLOCK` (`nonce_in_flight_or_used`). Rule `replay`. The reference ledger is in memory, so this holds within one process. Across processes it needs a shared atomic store. |
| Omitted or reordered receipts | When receipts carry `sequence` and `prevReceiptHash`, `verifyReceiptChain` detects a gap, an insertion, or a reorder inside the presented set. |
| Unauthorized execution | `BLOCK` and `REQUIRE_HUMAN` return before the executor. |
| Prompt injection that tries to raise the bound | Text in the intent is not a constraint. A spending action is checked against `max_amount` **per intent**. A sentence that says to ignore the limit does not raise the bound. |
| Receipt forgery under a known issuer key | The signature and the content hash cover the body, including `authority.chain` hashes and optional `sequence` / `prevReceiptHash`. A change to that body fails verification against the issuer key. |
| Policy substitution inside one receipt | The receipt binds the pin, the version, the rule id, and `policy.contentHash`. A different canonical policy document fails that hash. |

## Deployment boundary (credentials)

The in-process reference callback is for local testing. If the agent process holds the API credential, it can skip this path. That is outside what an in-process SDK can prevent.

A deployment that needs the boundary to hold runs the check **out of process**: a sidecar, an MCP server gateway, or a commercial enforcement gateway. The agent holds only the key it signs intents with. It holds no rail credential. The credential stays in the operator's vault, attached to a write endpoint that accepts a request only from the gateway, and only after `ALLOW`.

```
┌──────────────────┐   signed intent   ┌─────────────────────────┐
│ Agent process    │ ────────────────► │ ADAP gateway / sidecar  │
│ signing key only │                   │  verify + policy        │
│ no rail cred     │                   │  exclusive nonce claim  │
└──────────────────┘                   │  receipt                │
                                       └───────────┬─────────────┘
                                                   │ ALLOW only
                                                   ▼
                                       ┌─────────────────────────┐
                                       │ Operator write endpoint │
                                       │ credential in vault     │
                                       └─────────────────────────┘
```

The property holds only when the operator's network gives the agent no other route to that endpoint or credential. ADAP defines the authority semantics. This repository does not ship the gateway or the network policy.

## What this draft does not guarantee

- Malicious model behavior in general. The bound is checked. The model's other output is not.
- A compromised host or a runtime that skips this path, or that reports an execution which did not happen.
- Credential isolation when the agent process itself holds the rail credential. Use the out-of-process proxy pattern above.
- Cumulative spend across a delegation. `max_amount` is per intent, not a running total.
- Completeness of a receipt set when emitters omit `sequence` / `prevReceiptHash`. Standalone receipts verify individually. Detecting omission or reordering needs the optional hash chain.
- A dropped tail. A chain proves the receipts it contains are contiguous. It does not prove that later receipts were not withheld. That needs the latest receipt hash from somewhere the emitter does not control.
- Exactly-once execution after a crash. A claim left `pending` by a crash blocks that nonce. The action runs at most once. A retry is a new intent.
- A compromised private key. A signature made with a stolen key still verifies.
- Identity provisioning. An agent id is an opaque string. How a verifier learns which key belongs to that id is implementation-defined.
- A receipt check that does not hold the issuer public key. Structure and the content hash can match while the signature is forged.
- A malicious verifier that ignores a failed check.
- A resource server that performs the action without a valid receipt.
- A downstream agent that stays inside the authority it was actually given. Narrowing limits what it can receive. It does not make a narrowed agent honest.
- Recomputing `policy.contentHash` without the policy document. The hash is of the canonical document, not of one file's raw bytes. Two files with the same document and different whitespace hash the same. The pin alone does not identify the document.
- Arbitrary business logic beyond the delegation constraints and the policy that was evaluated.
- Availability. This draft does not specify rate limits or denial of service.
- Physical-world safety beyond the authorization decision.

The model can change its mind. The authority boundary cannot.

Normative narrowing rules: [spec/delegation.md](spec/delegation.md). Receipt binding: [spec/authorization-receipt.md](spec/authorization-receipt.md). Reference path: `packages/aap/src/validate.ts` and `packages/aap/src/path.ts`.
