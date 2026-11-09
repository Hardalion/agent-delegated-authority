# Authorization Receipt

**Status:** Public Draft (v0.1). Cryptography in §5 is the reference profile.  
**Kind:** `adap.receipt`  
**License:** Apache 2.0

This document defines the portable record of authorization produced at a consequential agent action: before a side effect when the decision is `BLOCK` or `REQUIRE_HUMAN`, and when the decision is `ALLOW`.

It records who attempted what, under which delegation hashes, under which policy version, whether a person approved, and whether the governing runtime reported execution. `executed: true` is that report. It is not an independent proof that an external system performed the side effect.

The normative requirements are the receipt structure and these bindings: intent, authority when a delegation chain was presented, policy, decision, and human approval when a person was required. Verification succeeds only when those bindings match and the signature checks under the profile the implementation states. This repository's reference profile is Ed25519, SHA-256, and canonical JSON (§5). Another profile is conforming when it preserves the bindings and states its algorithms.

Organization identifiers, residual scores, and replay anchors are not part of this schema. Extensions MAY add implementation-specific metadata. A conforming verifier does not interpret `extensions`.

---

## 1. Problem

A verifier needs to answer:

> At time T, agent A attempted action Y under policy Z and under this delegation chain. Was it authorized? By which rule version? Did a person approve? Did the governing runtime report execution?

The receipt is a self-contained, signed, offline-verifiable record of that answer, including when the action was blocked and the runtime reported that nothing executed.

---

## 2. Design goals

1. **Bindings.** The receipt names the intent, the delegation hashes when a chain was presented, the policy version, the decision, whether a person approved, and whether the governing runtime reported execution.
2. **Offline verification.** A verifier checks those bindings and the signature without a network call.
3. **Fail-closed.** A consequential action without a valid receipt is a conformance failure.

The reference profile in §5 fixes one way to hash and sign. Package names in this repository are not part of the normative semantics.

---

## 3. Format version

| Field | Value |
|-------|-------|
| `v` | `1` |
| `kind` | `adap.receipt` |

---

## 4. Schema

### 4.1 Top-level object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | `1` | yes | Format version |
| `kind` | `"adap.receipt"` | yes | Discriminator |
| `receiptId` | string (≤128) | yes | Stable unique id for this receipt |
| `issuer` | string (≤256) | yes | Id of the runtime that signed the receipt |
| `issuerKeyId` | string (≤256) | yes | Public key id / fingerprint used for `signature` |
| `decidedAt` | ISO-8601 datetime | yes | Decision timestamp (UTC) |
| `intent` | `ActionIntent` | yes | What the agent attempted |
| `identity` | `AgentIdentity` | yes | Who attempted it |
| `authority` | `AuthorityBinding` | no | Required when a delegation chain was presented. Binds each unsigned delegation by hash |
| `policy` | `PolicyRef` | yes | Which policy was evaluated |
| `decision` | `AuthorizationDecision` | yes | Outcome |
| `human` | `HumanAttestation` | no | Required when a person had to approve before `ALLOW` |
| `execution` | `ExecutionBinding` | no | Whether anything executed, and the target label |
| `integrity` | `ReceiptIntegrity` | yes | Content hash of the unsigned body |
| `sequence` | number | no | Non-negative integer position in an issuer receipt log. When present with `prevReceiptHash`, receipts form a verifiable hash chain |
| `prevReceiptHash` | string \| null | no | SHA-256 `integrity.contentHash` of the previous receipt in that log, or `null` for the first. Covered by this receipt's content hash and signature |
| `extensions` | object | no | Implementation-specific metadata. Not required to verify the receipt |
| `signature` | string | yes | Signature over the unsigned body. Reference profile: 64-byte Ed25519, hex |

### 4.2 `ActionIntent`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `toolName` | string | yes | Tool or action name |
| `argsHash` | string | yes | Hash of the canonical tool arguments. Reference profile: SHA-256, 64 hex chars |
| `argsRedacted` | object | no | Optional redacted args for human review (never secrets) |
| `actionClass` | string | no | Optional label supplied by the caller |

### 4.3 `AgentIdentity`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agentId` | string | yes | Stable agent id |
| `agentRole` | string | no | Role / autonomy tier label |
| `principalId` | string | no | Human or service that delegated |
| `delegationChain` | string[] | no | Ordered subjects, parent to child. When `authority` is present, `delegationChain[i]` equals `authority.chain[i].subject` |
| `actorType` | `"non_human_agent"` \| `"human"` \| `"system"` | yes | Audit actor class |

### 4.3a `AuthorityBinding`

Present when the runtime presented a delegation chain. The signature covers these hashes. A verifier that also holds an unsigned delegation checks that its reference-profile hash equals `chain[i].hash`. Receipt verification alone does not re-fetch the delegation.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `principalId` | string | yes | Issuer of the root delegation. Equals `identity.principalId` when both are present |
| `chain` | `AuthorityLink[]` | yes | Parent to child. Non-empty |

`AuthorityLink`:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `delegationId` | string | yes | `delegation_id` of the presented grant |
| `subject` | string | yes | Who received that grant |
| `hash` | string | yes | Reference-profile hash of the unsigned delegation. SHA-256 over canonical JSON, 64 hex chars |

### 4.4 `PolicyRef`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policyUri` | string | yes | Policy pin `{policy-id}@{semver}`. A URI scheme is implementation-defined and is not part of this draft |
| `policyName` | string | yes | Kebab-case policy id |
| `policyVersion` | string | yes | Semver or rule-set version string |
| `ruleId` | string | yes | Matched rule id, `agent_not_in_scope`, `default_allow`, or `default_` plus the action |
| `contentHash` | string | yes | SHA-256 of the policy document in canonical JSON, 64 hex chars. This is the document the runtime loaded, not the raw bytes of one file. When `ruleId` is a policy rule, that document produced the decision. When the decision is a delegation failure, the hash still names the document that was loaded and not applied. A verifier who holds the document recomputes the hash. The pin alone does not identify those bytes |

### 4.5 `AuthorizationDecision`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `action` | `ALLOW` \| `BLOCK` \| `REQUIRE_HUMAN` \| `DEFER` \| `SIMULATE` | yes | Decision verb |
| `outcome` | `allowed` \| `rejected` \| `deferred` \| `pending_human` | yes | Normalized enforcement outcome |
| `reason` | string (≤2000) | yes | Human-readable reason |
| `alertSeverity` | `LOW` \| `MEDIUM` \| `CRITICAL` | yes | Severity from the matched rule |
| `failureMode` | `NONE` \| `RULE_VIOLATION` \| `MAPPING_FAILED` \| `SYSTEM_ERROR` | no | Why a decision failed, when it did |
| `matched` | boolean | yes | Whether a rule matched |

**Normalization:**

| Source | `action` | `outcome` |
|--------|----------|-----------|
| `ALLOW` | `ALLOW` | `allowed` |
| `BLOCK` | `BLOCK` | `rejected` |
| `REQUIRE_HUMAN` | `REQUIRE_HUMAN` | `pending_human` |
| `DEFER` | `DEFER` | `deferred` |
| `SIMULATE` | `SIMULATE` | `allowed` |

**Semantic invariants (verifier must reject):**

- `decision.outcome` must equal the normalized outcome for `decision.action`
- `execution.executed=true` only with `action=ALLOW` (and not with rejected/pending/deferred outcomes)
- `BLOCK`, unresolved `REQUIRE_HUMAN`, `DEFER`, and `SIMULATE` must not claim live execution
- `REQUIRE_HUMAN` receipts must include `human` with `required=true`
- `ALLOW` must not claim `human.status=pending`
- `execution.executedAt` requires `execution.executed=true`

A structurally valid receipt with a valid issuer signature means the issuer attested that body. It is not independent proof that a downstream system performed a side effect unless `execution.executed` is true and consistent with the decision.

### 4.6 `ExecutionBinding`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `targetSystem` | string | no | Downstream label. `resource/example` in the synthetic example |
| `intentHash` | string | yes, when `execution` is present | Reference-profile hash of the unsigned intent presented at the execution boundary. SHA-256 over canonical JSON, 64 hex chars |
| `executed` | boolean | no | Whether the governing runtime reported a side effect. Not an independent observation of an external system |
| `executedAt` | ISO-8601 | no | Execution timestamp if committed |

### 4.7 `HumanAttestation`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `required` | boolean | yes | Whether a person had to approve |
| `status` | `pending` \| `approved` \| `declined` \| `escalated` | yes | |
| `approverId` | string | no | Human operator id |
| `decidedAt` | ISO-8601 | no | |
| `reason` | string | no | Mandatory decline / override reason when required by policy |
| `policyRef` | string | no | Optional policy citation on the approval |

### 4.8 `ReceiptIntegrity`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `contentHash` | string | yes | Hash of the unsigned body, excluding `signature` and with `integrity.contentHash` treated as empty (see §5). Reference profile: SHA-256, 64 hex chars |

---

## 5. Reference profile

Normative verification semantics:

1. Check `v`, `kind`, required fields, and enums.
2. Recompute the content hash of the unsigned body and compare it to `integrity.contentHash`.
3. Verify `signature` with the public key identified by `issuerKeyId`.
4. Confirm the receipt binds the intent, the policy pin and `ruleId`, the decision, and `human` when a person was required.
5. Do not call a network.

The reference profile implemented by `packages/audit-verify` is:

1. Build the unsigned object without `signature` and with `integrity.contentHash` set to `""`.
2. Canonical JSON is RFC 8785 (JCS). Object members are written in ascending UTF-16 code-unit order directly from the sorted entries. The serializer does not rebuild a JavaScript object and then enumerate it, because integer-like keys would otherwise come out in numeric order. UTF-8. No insignificant whitespace. Finite numbers use ECMAScript Number-to-String, the same conversion as `JSON.stringify`: `500.0` is `500`, `1e-7` stays `1e-7`, and negative zero is `0`. Non-finite numbers, lone surrogates, BigInt, functions, and symbols are rejected. Undefined object members are omitted and do not enter the encoding. Dangerous keys (`__proto__`, `constructor`, `prototype`) and objects whose prototype is not `Object.prototype` or `null` are rejected. Shared vectors: `packages/audit-verify/src/canonical-json.vectors.json`. An independent check is `scripts/verify-canonical-json.py`.
3. `contentHash = hex(SHA-256(utf8(canonicalJson)))`.
4. Replace the placeholder with that `contentHash`.
5. Canonicalize again, still without `signature`.
6. `signature = hex(Ed25519.Sign(issuerPrivateKey, utf8(canonicalJson)))`.

`issuerKeyId` names the public key. The reference profile does not define a hosted key directory.

Receipt verbs still include `DEFER` and `SIMULATE` so already issued receipts remain verifiable. v0.1 policy evaluation does not produce those actions. See [policy-schema.md](./policy-schema.md).

Compatibility: objects whose keys are not integer-index strings canonicalize to the same bytes as the previous reference profile. `examples/receipt.json` still has content hash `35a2f27d1d11b306fbbfa81d0345afe66db6c9087d760eec7f20644744f2511c`. Keys that are integer-index strings were previously emitted in numeric order (`"9"` before `"10"`). They are now lexicographic (`"10"` before `"9"`), which is what RFC 8785 requires. A receipt, tool-argument hash, or signature that covered such keys was bound to the old order and must be re-issued. The published example receipt does not use those keys.

---

## 6. When to emit

| Event | Emit receipt? | `executed` |
|-------|---------------|------------|
| Gate `BLOCK` | Yes | `false` |
| Gate `REQUIRE_HUMAN` (pause) | Yes | `false` |
| Gate `DEFER` | Yes | `false` |
| Gate `ALLOW`, then execution | Yes | `true` after execution |
| Human approve, then execution | Yes. A new receipt with `human.status` approved | `true` |
| `SIMULATE` | Yes | `false` |

Conforming runtimes do not perform a consequential side effect unless the governing receipt is `ALLOW` with `executed: true`.

---

## 7. Verification scope

A receipt is verified on its own. This draft does not define a store, an index, or a telemetry pipeline.

When an emitter sets `sequence` and `prevReceiptHash`, consecutive receipts form a hash chain: each signed body includes the prior receipt's `integrity.contentHash`. A verifier walks the ordered set: `sequence` increases by one, each `prevReceiptHash` names the previous receipt, and every receipt is from the same issuer key. That detects omission, insertion, and reordering inside the set. It does not detect a dropped tail. The verifier needs the expected latest receipt from somewhere the emitter does not control. Reference: `verifyReceiptChain` in `packages/audit-verify`.

Standalone receipts without those fields remain conforming. They do not, by themselves, prove that none were omitted.

---

## 8. Conformance

A conforming emitter:

1. Uses this schema with `kind: adap.receipt` and `v: 1`
2. Binds the intent, the policy pin and `ruleId`, the decision, and human approval when a person was required
3. Signs under a stated profile. The reference profile is §5
4. Does not execute a consequential tool when the governing receipt is `BLOCK` or an unresolved `REQUIRE_HUMAN` / `DEFER`

A conforming verifier returns `{ valid, errors[] }` without network calls. `verifyAuthorizationReceipt` checks structure and the content hash. The Ed25519 signature is checked by a verifier that holds the issuer public key (`verifyReceiptSignature`, and `verifyProtocolReceipt` on the reference path). The `adap-receipt` CLI checks the signature only when `--public-key` is set. A check without that key has not completed §5 step 3.

---

## 9. Example

See [`../examples/receipt.json`](../examples/receipt.json).

---

Unknown fields are ignored by conforming verifiers.
