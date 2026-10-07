# Threat model

**Status:** Public Draft (v0.1).  
**License:** Apache 2.0

ADAP authorization correctness is not complete agent security.

A correct decision means the presented delegation, intent, and policy authorized or refused the action. It does not mean the surrounding system is safe.

The reference path stops these. Nothing else in this list is claimed.

- Over-delegation. A child cannot raise the parent's bound.
- Privilege escalation. A capability marked `delegable: false` cannot be passed on.
- Replay. A consumed nonce cannot authorize the action again.
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
| Replay | A consumed nonce cannot authorize the action again. Rule `replay`. |
| Unauthorized execution | `BLOCK` and `REQUIRE_HUMAN` return before the executor. |
| Prompt injection that tries to raise the bound | Text in the intent is not a constraint. A spending action is checked against `max_amount`. A sentence that says to ignore the limit does not raise the bound. |
| Receipt forgery under a known issuer key | The signature and the content hash cover the body, including `authority.chain` hashes. A change to that body fails verification against the issuer key. |
| Policy substitution inside one receipt | The receipt binds the pin, the version, the rule id, and `policy.contentHash`. A different canonical policy document fails that hash. |

## What this draft does not guarantee

- Malicious model behavior in general. The bound is checked. The model's other output is not.
- A compromised host or a runtime that skips this path, or that reports an execution which did not happen.
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
