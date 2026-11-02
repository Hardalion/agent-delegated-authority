> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-IMPLEMENTATION-REVIEW

What the code on this working tree actually does. Not what the previous remediation report claimed.

## Protocol guarantee

The specs now say:

- A child grant cannot widen a parent grant.
- A human approval is bound to intent hash, agent, delegation-chain hash, and policy content hash.
- Amounts are non-negative safe integers.
- A receipt with contradictory action, outcome, and execution is not valid.
- `max_amount` is per intent, not cumulative.

Those sentences are only true for inputs that survive the reference functions below. The protocol does not, by itself, stop a process that never calls those functions.

## Reference implementation guarantee

`runAuthorityPath` does the following for a plain JSON-like object that the caller does not mutate:

1. Validates shape, nonce, identity, amount, and target.
2. Verifies delegation and intent signatures.
3. Checks expiry against `clock` or `now`.
4. Refuses object nonces.
5. On `REQUIRE_HUMAN`, writes a pending record and returns before `execute`.
6. On continuation, requires that pending record and a signature over the approval binding. A different policy object does not turn the pending decision into `ALLOW` when a resolver is pinned, and does not turn it into `ALLOW` with no approval.
7. Claims the nonce synchronously before `await input.execute`.
8. A second in-process caller with the same nonce does not enter `execute`.
9. `BLOCK` and an unresolved `REQUIRE_HUMAN` do not call `execute`.
10. The receipt verifier rejects the contradictory combinations that were probed.

It does **not** do the following:

1. It does not execute the verified snapshot. `executeBound` spreads `input.intent.parameters` after authorization. Nested objects remain shared with the caller. RT-01.
2. It does not treat schema failures before signature verification as unauthenticated. Those failures can consume the nonce. RT-03.
3. It does not catch canonicalization failures that happen before the `try`. `NaN` rejects the promise. RT-04.
4. It does not provide a distributed nonce or pending store. The classes are process-local `Map`s.
5. It does not prove that a downstream system performed the action. `executed: true` means the callback returned.
6. It does not stop the caller from passing `now`.
7. It does not ignore a caller-supplied policy unless that URI was already registered on the resolver. The first `register` for a URI wins.

## Deployment guarantee

Required outside this repository if the authority boundary is meant to hold:

- The agent process does not hold the downstream credential and cannot call the write API except through the gateway.
- The gateway parses the request into its own objects (or deep-copies and freezes them) before `runAuthorityPath`. RT-01 is the reason.
- The gateway's clock is the host clock. Agent timestamps are not passed as `now`.
- Nonce and pending state are one atomic store shared by every gateway instance. This tree does not provide that store.
- Policy documents are registered by the operator before requests are served.
- Approver public keys in the directory are provisioned by the operator.

## Unsafe defaults that remain intentional

- A policy with no `defaultAction` still defaults to `ALLOW` inside `evaluatePolicy`. The example policies set `BLOCK`. A policy author who omits the field does not fail closed.
- `evaluateToolCall` without `agentRole` does not apply `targetAgents`. `runAuthorityPath` does pass the actor.
- `seenApprovals` is optional. After a successful execution the nonce is spent, so a second presentation does not execute. The set is not required for single execution inside one process.

## Proposed fixes (not applied)

This audit did not patch these. They are the smallest changes that match the findings:

1. Build the execution context, the receipt arguments, and the intent hash from `verified.intent` after a deep copy that does not share nested objects with the caller. Freeze that copy.
2. Mark pre-signature schema errors `authenticated: false`, or verify the signature before any path that consumes a nonce.
3. Move hash computation inside the `try`, or catch canonicalization errors and return `BLOCK` without throwing.
4. Add probes RT-01, RT-03, and RT-04 to the permanent suite. The current suite stays green without them.

## After the RT-01 / RT-03 / RT-04 patch

The three "does not" sentences numbered 1–3 above described the tree at audit time. The patch changes those three behaviors. Sentences 4–7 are unchanged.

`runAuthorityPath` now does this:

1. `presentAuthority` deep-copies the chain and the intent, rejects cycles, non-plain prototypes, unsupported types, and dangerous keys, checks the canonical form, then verifies signatures. Failures here set no `signatureVerified` flag.
2. Only after that flag is set does the path hash the signed snapshot and call `assertUsable` on its nonce.
3. `authorizePresented` then checks amounts, delegation narrowing, and expiry. Those failures are authenticated. The path may consume the snapshot nonce and seal a `BLOCK` receipt.
4. Policy arguments, the executor parameters, and the receipt arguments are deep copies of the frozen validated snapshot. `executeBound` does not read `input.intent` from the caller. The object passed into `execute` is a second copy, so the executor can mutate its copy without changing the receipt.
5. A failure before signature verification returns `decision: BLOCK`, `authenticated: false`, `executed: false`, and no `receipt`. The nonce is not consumed. The reason for `NaN` and the infinities is `intent could not be canonicalized`. A cycle names the path. A bad signature says `intent signature invalid`.
6. If sealing an authenticated failure itself throws, `sealOrClosed` returns a structured `BLOCK` with no receipt instead of rejecting the promise.

What this patch does not add:

- A shared or durable nonce store. `NonceLedger` is still one process-local `Map`.
- A check that `now` is the host clock.
- A change to `evaluateToolCall` when `agentRole` is omitted.
- Distributed atomicity. The claim is still synchronous only inside one process, before `await input.execute`.
