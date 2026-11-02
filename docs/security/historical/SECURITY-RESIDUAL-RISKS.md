> **Historical snapshot.** This file records an earlier audit or local drill. It is not the current state of `main`.
> Notes that name `1fa576a` or `security/adap-complete-remediation` describe that earlier tree.
> Current status: [Security status](../status.md).

# SECURITY-RESIDUAL-RISKS

What remains after the final hardening pass. Ordered by severity for operators.

## Deployment requirements (not implemented as a shared store here)

| Item | Severity | Detail |
| --- | --- | --- |
| Distributed nonce / pending store | High for multi-process deploy | `SharedNonceLedger` + `AsyncAtomicNonceBackend` define the contract. Default `NonceLedger` is one process-local map. Two OS processes with separate backends do not coordinate. |
| Credential isolation | High if ignored | If the agent holds the rail credential, it can skip `runAuthorityPath`. |
| Trusted clock ownership | Medium | Gateway must inject a host clock it controls, or rely on `systemClock`. Never forward agent timestamps into `clock.now()`. Zero skew tolerance. |
| Policy registry ownership | Medium | Only the operator registers policies. The path refuses unknown URIs and refuses a caller body that disagrees with the pin. |

## Reference-implementation limits

| Item | Severity | Detail |
| --- | --- | --- |
| Receipt ≠ external observation | Medium | `executed: true` means the callback returned. It is not proof of an external system commit. |
| Executor throw after partial write | Medium | Path records `executed: false` and spends the nonce. Downstream writes must be idempotent or reconcilable. |
| Unhashable executor result | Low | Path reports `executed: true`, `executionHash: unhashable`, no receipt body; nonce consumed. |
| Receipt chain truncation | Low | A withheld tail is still undetectable by a verifier that only sees the presented suffix. |
| Cumulative spend | Low | `max_amount` is per intent. |
| Approval revocation list | Low | Not implemented. Approver keys live in the caller-supplied directory. |

## Intentionally unchanged

| Item | Note |
| --- | --- |
| Wildcard `targetAgents: ["*"]` | Still matches any **well-formed** role. Omitted/empty roles do not match. |
| Case-sensitive targets | `resource/Example` ≠ `resource/example`. No silent case fold. |
| Attack catalogue scope | Six narrative attacks only. Broader coverage is in the vitest adversarial suites. |

## Not accepted as open authority bypasses

- RT-01 / RT-03 / RT-04 original PoCs.
- RT-06 caller `now` revival.
- RT-08 omitted `agentRole` under a scoped or wildcard policy.
- `resource/.` and `resource/./vault` under a one-segment wildcard.
- Missing `defaultAction` evaluating to ALLOW.
- Silent re-registration of a different policy document under the same URI.

## Claim ceiling

Do not claim:

- production secure / fully secure;
- distributed replay protection without a tested shared atomic store;
- that unauthorized execution is impossible in every network;
- that a green CI audit means dependencies stay clean forever.
